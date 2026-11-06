import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest

import amaterasu_limiter
from policy_store import PolicyStore


class PolicyStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="amaterasu-policy-store-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.policy = {"app_id": None, "provider": "proton", "limit_millihz": 59940,
                       "preset": "custom", "method": "late", "graph": False}

    def test_policy_is_visible_to_hook_and_removed_on_close(self):
        store = PolicyStore(self.root)
        store.set("session", None, "r1", self.policy)
        env = {"XDG_RUNTIME_DIR": str(self.root)}
        namespace = {"g_session": types.SimpleNamespace(env=env)}
        self.assertTrue(amaterasu_limiter.apply(namespace))
        self.assertEqual(env["VKD3D_FRAME_RATE"], "59.94")
        store.close()
        self.assertFalse(store.path.exists())
        self.assertFalse(amaterasu_limiter.apply(namespace))

    def test_only_one_writer_and_removal_retires_policy(self):
        with PolicyStore(self.root) as store:
            store.set("session", None, "r1", self.policy)
            with self.assertRaises(BlockingIOError):
                PolicyStore(self.root)
            store.remove("session", "r1")
            self.assertFalse(store.path.exists())
        with PolicyStore(self.root) as replacement:
            replacement.set("next", None, "r2", self.policy)
            self.assertTrue(replacement.path.exists())

    def test_external_modification_is_never_overwritten_or_deleted(self):
        store = PolicyStore(self.root)
        store.set("session", None, "r1", self.policy)
        external = {"version": 1, "owner": {"pid": os.getpid(), "start_ticks": 1,
                    "expires_unix_ms": 1}, "policies": [], "other": "preserve"}
        store.path.write_text(json.dumps(external), encoding="utf-8")
        with self.assertRaises(ValueError):
            store.refresh()
        store.close()
        self.assertEqual(json.loads(store.path.read_text(encoding="utf-8")), external)

    def test_stale_cleanup_cannot_remove_a_newer_policy(self):
        with PolicyStore(self.root) as store:
            store.set("session", None, "r1", self.policy)
            updated = dict(self.policy, limit_millihz=120000)
            store.set("session", "r1", "r2", updated)
            with self.assertRaises(ValueError):
                store.remove("session", "r1")
            with self.assertRaises(ValueError):
                store.set("session", "r1", "r3", self.policy)
            with self.assertRaises(ValueError):
                store.set("session", "r2", "r2", self.policy)
            self.assertEqual(json.loads(store.path.read_text())["policies"], [updated])
            store.set("session", "r1", "r2", updated)
            store.remove("session", "r2")
            self.assertFalse(store.path.exists())

    def test_stale_recognized_state_can_be_recovered_but_unknown_state_cannot(self):
        with PolicyStore(self.root) as store:
            state_dir = store.directory
        state = state_dir / "active.json"
        state.write_text(json.dumps({"version": 1, "owner_id": "standalone", "owner": {"pid": os.getpid(),
                         "start_ticks": amaterasu_limiter._process_start(os.getpid()),
                         "expires_unix_ms": time.time_ns() // 1_000_000 - 1}, "policies": []}), encoding="utf-8")
        state.chmod(0o600)
        with PolicyStore(self.root) as store:
            store.set("session", None, "r1", self.policy)
            self.assertEqual(json.loads(state.read_text())["policies"][0], self.policy)
        state.write_text("{}", encoding="utf-8")
        state.chmod(0o600)
        with self.assertRaises(ValueError):
            PolicyStore(self.root)
        self.assertEqual(state.read_text(), "{}")

    def test_symlink_state_and_unsafe_runtime_directory_are_rejected(self):
        with PolicyStore(self.root) as store:
            target = store.directory / "target"
            target.write_text("{}", encoding="utf-8")
            store.path.symlink_to(target)
            with self.assertRaises(OSError):
                store.set("session", None, "r1", self.policy)
            store.path.unlink()
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):
            PolicyStore(self.root)

    def test_recovery_accepts_only_owned_journaled_policy_snapshots(self):
        before = self.policy
        after = dict(before, limit_millihz=120000)
        with PolicyStore(self.root) as store:
            path = store.path
            store.set("session", None, "r1", before)
            state = json.loads(path.read_text())
            state["owner"]["expires_unix_ms"] = 0
            path.write_text(json.dumps(state))
        for expected in ([[before], [after]], [[after], [before]]):
            path.write_text(json.dumps(state))
            with PolicyStore(self.root, "standalone", expected) as recovered:
                recovered.refresh()
                self.assertFalse(path.exists())
        for change in ("owner", "policy", "legacy"):
            foreign = json.loads(json.dumps(state))
            if change == "owner":
                foreign["owner_id"] = "someone-else"
            elif change == "legacy":
                del foreign["owner_id"]
            else:
                foreign["policies"] = [dict(before, limit_millihz=144000)]
            content = json.dumps(foreign)
            path.write_text(content)
            with self.assertRaises(ValueError):
                PolicyStore(self.root, "standalone", [[before], [after]])
            self.assertEqual(path.read_text(), content)


if __name__ == "__main__":
    unittest.main()
