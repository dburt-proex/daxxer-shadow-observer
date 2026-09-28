"""Contained storage and OS-released locks. No third-party dependencies."""
from contextlib import contextmanager
import os
from pathlib import Path


class StorageError(ValueError):
    pass


def safe_path(root, relative):
    root = Path(root).absolute()
    part = Path(relative)
    if part.is_absolute() or part.drive or '..' in part.parts:
        raise StorageError('storage path must be relative and contained')
    target = root / part
    for candidate in [root, *[root.joinpath(*part.parts[:i]) for i in range(1, len(part.parts) + 1)]]:
        if candidate.is_symlink() or (candidate.exists() and getattr(candidate.lstat(), 'st_file_attributes', 0) & 0x400):
            raise StorageError('linked storage paths are forbidden')
    if not target.resolve().is_relative_to(root.resolve()):
        raise StorageError('storage path escapes component')
    return target


@contextmanager
def file_lock(path):
    """Nonblocking advisory lock; crashes release it without deleting the file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    locked = False
    try:
        if os.name == 'nt':
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b'0')
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        yield
    except OSError as exc:
        raise StorageError('storage lock or IO operation failed') from exc
    finally:
        if locked:
            if os.name == 'nt':
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
