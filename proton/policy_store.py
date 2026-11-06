"""Own a bounded, expiring runtime policy for the Proton launch hook."""

import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile
import time

import amaterasu_limiter


class PolicyStore:
    """One process holds the lock and refreshes all its session policies.

    The store must be refreshed at least every 60 seconds. A dead or stalled
    owner therefore leaves hooks inert without changing Proton settings again.
    """

    def __init__(self, runtime_root, owner_id="standalone", expected_policies=None):
        if (not isinstance(owner_id, str) or not 1 <= len(owner_id) <= 128
                or any(ord(char) < 33 or ord(char) > 126 for char in owner_id)):
            raise ValueError("invalid policy owner identity")
        self.owner_id = owner_id
        self.expected_policies = expected_policies
        root = Path(runtime_root)
        if not root.is_absolute():
            raise ValueError("runtime root must be absolute")
        self._check_directory(root)
        parent = root
        for part in ("amaterasu", "frame-limiter"):
            parent = parent / part
            try:
                parent.mkdir(mode=0o700)
            except FileExistsError:
                pass
            self._check_directory(parent)
        self.directory = parent
        self.path = parent / "active.json"
        self.lock_fd = os.open(parent / "active.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        self._owned_inode = None
        self._policies = {}
        try:
            self._check_regular(os.fstat(self.lock_fd))
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._check_previous_state()
        except BaseException:
            os.close(self.lock_fd)
            self.lock_fd = None
            raise

    @staticmethod
    def _check_directory(path):
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o022):
            raise ValueError("runtime directory is not privately owned")

    @staticmethod
    def _check_regular(info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o022):
            raise ValueError("runtime state is not privately owned")

    def _read_current(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None, None
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            self._check_regular(info)
            content = source.read(16385)
        if len(content) > 16384:
            raise ValueError("runtime state is too large")
        return json.loads(content), (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def _check_previous_state(self):
        state, inode = self._read_current()
        if state is None:
            return
        if not isinstance(state, dict) or state.get("version") != 1 or not isinstance(state.get("owner"), dict):
            raise ValueError("unrecognized runtime state")
        if state.get("owner_id") != self.owner_id:
            raise ValueError("runtime state belongs to a different owner")
        if self.expected_policies is not None:
            canonical = lambda policies: sorted(json.dumps(policy, sort_keys=True, separators=(",", ":")) for policy in policies)
            if (not isinstance(self.expected_policies, list) or len(self.expected_policies) > 2
                    or not isinstance(state.get("policies"), list)
                    or not any(canonical(state["policies"]) == canonical(expected) for expected in self.expected_policies)):
                raise ValueError("runtime policy differs from the journaled intent")
        owner = state["owner"]
        if (type(owner.get("pid")) is not int or owner["pid"] < 1
                or type(owner.get("start_ticks")) is not int
                or type(owner.get("expires_unix_ms")) is not int
                or not isinstance(state.get("policies"), list)):
            raise ValueError("unrecognized runtime owner")
        try:
            active = (owner["expires_unix_ms"] > time.time_ns() // 1_000_000
                      and amaterasu_limiter._process_start(owner["pid"]) == owner["start_ticks"])
        except (OSError, ValueError, TypeError, KeyError, IndexError):
            active = False
        if active:
            raise ValueError("another live owner has runtime state")
        self._owned_inode = inode

    @staticmethod
    def _valid_revision(revision):
        return (isinstance(revision, str) and 1 <= len(revision) <= 128
                and all(0x21 <= ord(char) <= 0x7e for char in revision))

    def set(self, session, expected_revision, revision, policy):
        if (not isinstance(session, str) or not 1 <= len(session) <= 128
                or any(ord(char) < 32 for char in session)):
            raise ValueError("invalid session identity")
        if not isinstance(policy, dict):
            raise ValueError("invalid policy")
        if (not self._valid_revision(revision)
                or (expected_revision is not None and not self._valid_revision(expected_revision))):
            raise ValueError("invalid policy revision")
        # Validate through the same policy projection used by Proton.
        amaterasu_limiter._edits(policy, {})
        app_id = policy.get("app_id")
        if app_id is not None and (not isinstance(app_id, str) or not app_id.isascii()
                                   or not app_id.isdigit() or len(app_id) > 10):
            raise ValueError("invalid app identity")
        if session not in self._policies and len(self._policies) >= 32:
            raise ValueError("policy capacity exceeded")
        current = self._policies.get(session)
        if current is not None and current[0] == revision:
            if current[1] == policy:
                return
            raise ValueError("policy revision conflict")
        if (current[0] if current is not None else None) != expected_revision:
            raise ValueError("stale policy revision")
        previous = self._policies.copy()
        self._policies[session] = (revision, dict(policy))
        try:
            self.refresh()
        except BaseException:
            self._policies = previous
            raise

    def remove(self, session, expected_revision):
        if not self._valid_revision(expected_revision):
            raise ValueError("invalid policy revision")
        current = self._policies.get(session)
        if current is None:
            return
        if current[0] != expected_revision:
            raise ValueError("stale policy revision")
        previous = self._policies.copy()
        self._policies.pop(session, None)
        try:
            self.refresh()
        except BaseException:
            self._policies = previous
            raise

    def for_application(self, app_id):
        """Read only the live owner's policy, with the same conflict rules as files."""
        _, current_inode = self._read_current()
        if current_inode != self._owned_inode:
            raise ValueError("runtime state changed externally")
        return amaterasu_limiter._select_policy(
            [entry[1] for entry in self._policies.values()], app_id)

    def refresh(self):
        if self.lock_fd is None:
            raise ValueError("policy store is closed")
        _, current_inode = self._read_current()
        if current_inode != self._owned_inode:
            raise ValueError("runtime state changed externally")
        if not self._policies:
            if current_inode is not None:
                self.path.unlink()
            self._owned_inode = None
            return
        now = time.time_ns() // 1_000_000
        state = {"version": 1, "owner_id": self.owner_id, "owner": {"pid": os.getpid(),
                 "start_ticks": amaterasu_limiter._process_start(os.getpid()),
                 "expires_unix_ms": now + 60_000},
                 "policies": [entry[1] for entry in self._policies.values()]}
        encoded = json.dumps(state, separators=(",", ":")).encode("utf-8")
        if len(encoded) > 16384:
            raise ValueError("runtime state is too large")
        fd, temporary = tempfile.mkstemp(prefix=".active-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            _, checked_inode = self._read_current()
            if checked_inode != current_inode:
                raise ValueError("runtime state changed externally")
            os.replace(temporary, self.path)
            _, self._owned_inode = self._read_current()
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def close(self):
        if self.lock_fd is None:
            return
        try:
            _, inode = self._read_current()
            if inode is not None and inode == self._owned_inode:
                self.path.unlink()
        finally:
            os.close(self.lock_fd)
            self.lock_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
