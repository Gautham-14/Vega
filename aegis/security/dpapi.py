"""Windows current-user DPAPI wrapper for the local control key."""
import ctypes
from ctypes import wintypes
import os


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _call(data: bytes, *, decrypt: bool) -> bytes:
    if os.name != "nt":
        raise OSError("DPAPI requires Windows")
    buffer = ctypes.create_string_buffer(data)
    incoming = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    outgoing = DATA_BLOB()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    if decrypt:
        operation = crypt.CryptUnprotectData
        operation.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
                              ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
        args = (ctypes.byref(incoming), None, None, None, None, 1, ctypes.byref(outgoing))
    else:
        operation = crypt.CryptProtectData
        operation.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.c_wchar_p, ctypes.c_void_p,
                              ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
        args = (ctypes.byref(incoming), "Aegis control key", None, None, None, 1, ctypes.byref(outgoing))
    operation.restype = wintypes.BOOL
    if not operation(*args):
        raise OSError(ctypes.get_last_error(), "Windows DPAPI could not protect or open the control key")
    try:
        return ctypes.string_at(outgoing.pbData, outgoing.cbData)
    finally:
        free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
        free.argtypes = [ctypes.c_void_p]
        free.restype = ctypes.c_void_p
        free(outgoing.pbData)


def protect(data: bytes) -> bytes:
    return _call(data, decrypt=False)


def unprotect(data: bytes) -> bytes:
    return _call(data, decrypt=True)
