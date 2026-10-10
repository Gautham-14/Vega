"""OS lock shared by the API lifetime and offline backup/key administration."""

import os
from contextlib import contextmanager

from aegis.security.private_files import no_links, restrict_permissions


@contextmanager
def exclusive(purpose, lock_path=None):
    if lock_path is None:
        from aegis import config

        config.initialize_storage()
        lock_path = config.DATA_DIR / "runtime.lock"
    path = no_links(lock_path)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    locked = False
    try:
        # Offline Linux host administration can lock an existing runtime-owned
        # file without changing its owner or weakening its permissions.
        if os.name != "posix" or os.geteuid() != 0 or path.stat().st_uid == 0:
            restrict_permissions(path)
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"0")
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError:
            raise RuntimeError(
                "Stop Aegis and any concurrent offline administration before " + purpose
            ) from None
        yield
    finally:
        if locked:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
