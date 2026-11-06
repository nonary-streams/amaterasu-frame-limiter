"""Install the plugin's inert-unless-owned Proton hook into one writable tool.

Only caller-supplied Proton installations are touched. This module does not
discover tools or create active policies; those are lifecycle responsibilities.
"""

import fcntl
import hashlib
import os
from pathlib import Path
import stat
import tempfile


_HELPER = "_amaterasu_frame_limiter_v1.py"
_BEGIN = b"# BEGIN Amaterasu frame limiter v1"
_END = b"# END Amaterasu frame limiter v1"
_BLOCK = b'''
# BEGIN Amaterasu frame limiter v1
try:
    import importlib.util as _am_limiter_import
    import pathlib as _am_limiter_path
    _am_limiter_spec = _am_limiter_import.spec_from_file_location(
        "_amaterasu_frame_limiter_v1", _am_limiter_path.Path(__file__).with_name("_amaterasu_frame_limiter_v1.py"))
    _am_limiter_module = _am_limiter_import.module_from_spec(_am_limiter_spec)
    _am_limiter_spec.loader.exec_module(_am_limiter_module)
    _am_limiter_module.apply(globals())
except Exception:
    pass
# END Amaterasu frame limiter v1
'''
_MAX_SETTINGS = 1024 * 1024
_PREVIOUS_HELPERS = {"fb8391eec24c922291babebc879892fa43ba2b72fcf192bf809c40dd5337d76a"}


def _regular_owned(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
            or info.st_mode & 0o022):
        raise ValueError("expected a singly linked user-owned regular file")
    return info


def _read_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = _regular_owned(source.fileno())
        data = source.read(_MAX_SETTINGS + 1)
    if len(data) > _MAX_SETTINGS:
        raise ValueError("file exceeds size limit")
    return data, info


def _same_file(left, right):
    return (left.st_dev, left.st_ino, left.st_size, left.st_mtime_ns, left.st_ctime_ns) == (
        right.st_dev, right.st_ino, right.st_size, right.st_mtime_ns, right.st_ctime_ns
    )


def _install_helper(tool, source):
    destination = tool / _HELPER
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        existing, original = _read_file(destination)
        if existing == source:
            return
        if hashlib.sha256(existing).hexdigest() not in _PREVIOUS_HELPERS:
            raise ValueError("existing limiter helper differs")
        if os.listxattr(destination, follow_symlinks=False):
            raise ValueError("helper has attributes that cannot be preserved")
        fd, temporary = tempfile.mkstemp(prefix=".amaterasu-helper-", dir=tool)
        try:
            with os.fdopen(fd, "wb") as output:
                if os.fstat(output.fileno()).st_gid != original.st_gid:
                    os.fchown(output.fileno(), -1, original.st_gid)
                os.fchmod(output.fileno(), stat.S_IMODE(original.st_mode))
                output.write(source)
                output.flush()
                os.fsync(output.fileno())
            current, info = _read_file(destination)
            if current != existing or not _same_file(original, info):
                raise ValueError("helper changed during upgrade")
            os.replace(temporary, destination)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        return
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(source)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise


def _update_settings(tool):
    path = tool / "user_settings.py"
    try:
        previous, original = _read_file(path)
    except FileNotFoundError:
        previous, original = b"", None
    if original is not None and os.listxattr(path, follow_symlinks=False):
        # Atomic replacement cannot reliably preserve every platform-specific
        # ACL or security label as an unprivileged user. Leave such files alone.
        raise ValueError("settings file has attributes that cannot be preserved")
    if _BEGIN in previous or _END in previous:
        if previous.count(_BEGIN) == previous.count(_END) == previous.count(_BLOCK) == 1:
            return
        raise ValueError("existing limiter hook was modified")
    updated = previous + _BLOCK
    compile(updated, str(path), "exec")
    fd, name = tempfile.mkstemp(prefix=".amaterasu-limiter-", dir=tool)
    staged = Path(name)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(updated)
            if original is not None:
                if os.fstat(output.fileno()).st_gid != original.st_gid:
                    os.fchown(output.fileno(), -1, original.st_gid)
                os.fchmod(output.fileno(), stat.S_IMODE(original.st_mode))
            output.flush()
            os.fsync(output.fileno())
        if original is None:
            # A no-replace link preserves a settings file created meanwhile.
            os.link(staged, path, follow_symlinks=False)
        else:
            current, current_info = _read_file(path)
            if not _same_file(original, current_info) or current != previous:
                raise ValueError("settings changed while installing hook")
            os.replace(staged, path)
    finally:
        try:
            staged.unlink()
        except FileNotFoundError:
            pass


def install(tool, helper_source):
    """Install a single tool hook without changing existing file permissions.

    An advisory lock serializes other instances of this installer. A writer
    that ignores the lock can still race the final comparison and replacement.
    """
    tool = Path(tool)
    info = tool.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise ValueError("Proton tool directory is not user-owned")
    if not (tool / "proton").is_file() or not (tool / "user_settings.sample.py").is_file():
        raise ValueError("not a recognized Proton tool")
    if not isinstance(helper_source, bytes) or len(helper_source) > _MAX_SETTINGS:
        raise ValueError("invalid helper source")
    compile(helper_source, _HELPER, "exec")
    lock_path = tool / ".amaterasu-frame-limiter.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        _regular_owned(fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _install_helper(tool, helper_source)
        _update_settings(tool)
        directory_fd = os.open(tool, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        os.close(fd)
