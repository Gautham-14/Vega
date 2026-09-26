"""Owner-only local files; never place a secret in a command-line argument."""
from __future__ import annotations

import ctypes
import ntpath
import os
from pathlib import Path
import re
import stat
import subprocess


def no_links(path: str | Path) -> Path:
    """Reject network/device paths before I/O, then links and reparse points."""
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or raw.replace("/", "\\").startswith("\\\\"):
        raise ValueError("Use a local filesystem path, not a network or device path")
    drive, tail = ntpath.splitdrive(raw)
    if (drive and (len(drive) != 2 or drive[1] != ":" or not drive[0].isalpha()
                   or not tail.startswith(("/", "\\")))):
        raise ValueError("Use an absolute local drive path")
    if ":" in tail or any(ord(c) < 32 for c in raw):
        raise ValueError("Alternate streams and control characters are not allowed")
    path = Path(os.path.abspath(raw))
    if os.name == "nt":
        drive_type = ctypes.windll.kernel32.GetDriveTypeW
        drive_type.argtypes, drive_type.restype = [ctypes.c_wchar_p], ctypes.c_uint
        if drive_type(path.anchor) not in {2, 3, 5, 6}:  # removable/fixed/CD/RAM; never mapped network drives
            raise ValueError("Storage must use an available local drive")
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise ValueError(f"Symbolic links and junctions are not allowed: {part}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError("Hard-linked files are not allowed")
    return path


def restrict_permissions(path: str | Path, directory: bool = False) -> None:
    """Apply current-user-only ACL on Windows, or 0700/0600 on POSIX."""
    path = no_links(path)
    if os.name != "nt":
        if path.stat().st_uid != os.getuid():
            raise PermissionError("Private storage must belong to the current user")
        path.chmod(0o700 if directory else 0o600)
        return
    result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True,
                            text=True, check=True, creationflags=0x08000000)
    sid = re.search(r"S-1-[0-9-]+", result.stdout)
    if sid is None:
        raise PermissionError("Cannot identify Windows user for private storage")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    descriptor = ctypes.c_void_p()
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_ulong)]
    convert.restype = ctypes.c_int
    flags = "OICI" if directory else ""
    if not convert(f"D:P(A;{flags};FA;;;{sid.group()})", 1, ctypes.byref(descriptor), None):
        raise PermissionError("Cannot create private Windows permissions")
    try:
        setter = advapi.SetFileSecurityW
        setter.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_void_p]
        setter.restype = ctypes.c_int
        if not setter(str(path), 0x80000004, descriptor):
            raise PermissionError("Cannot restrict private storage to current Windows user")
    finally:
        free = ctypes.WinDLL("kernel32").LocalFree
        free.argtypes, free.restype = [ctypes.c_void_p], ctypes.c_void_p
        free(descriptor)
