import json
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

import amaterasu_limiter
from policy_store import PolicyStore


class WorkerTests(unittest.TestCase):
    @staticmethod
    def read_reply(process):
        readable, _, _ = select.select([process.stdout], [], [], 5)
        if not readable:
            raise AssertionError("worker did not reply")
        return json.loads(process.stdout.readline())

    def test_abrupt_worker_death_makes_existing_hook_state_inert(self):
        with tempfile.TemporaryDirectory(prefix="amaterasu-limiter-worker-") as root:
            worker = Path(__file__).with_name("worker.py")
            process = subprocess.Popen([sys.executable, str(worker), root], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.addCleanup(lambda: process.poll() is None and process.kill())
            self.assertEqual(self.read_reply(process)["state"], "ready")
            policy = {"app_id": None, "provider": "proton", "limit_millihz": 59940,
                      "preset": "custom", "method": "late", "graph": False}
            process.stdin.write(json.dumps({"id": 1, "operation": "set", "session": "s", "expected_revision":None, "revision":"r1", "policy": policy}) + "\n")
            process.stdin.flush()
            self.assertEqual(self.read_reply(process)["state"], "stored")
            state = Path(root) / "amaterasu/frame-limiter/active.json"
            environment = {"XDG_RUNTIME_DIR": root}
            self.assertTrue(amaterasu_limiter.apply({"g_session": types.SimpleNamespace(env=environment)}))
            process.kill()
            process.wait(timeout=5)
            self.assertTrue(state.exists())
            environment = {"XDG_RUNTIME_DIR": root}
            self.assertFalse(amaterasu_limiter.apply({"g_session": types.SimpleNamespace(env=environment)}))
            with PolicyStore(root) as recovered:
                recovered.set("next", None, "r2", policy)
                self.assertTrue(amaterasu_limiter.apply({"g_session": types.SimpleNamespace(env=environment)}))
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()

    def test_multiple_requests_are_processed_and_policy_is_retired_on_eof(self):
        with tempfile.TemporaryDirectory(prefix="amaterasu-limiter-worker-") as root:
            worker = Path(__file__).with_name("worker.py")
            policy = {"app_id": None, "provider": "proton", "limit_millihz": 59940,
                      "preset": "custom", "method": "late", "graph": False}
            messages = [
                {"id": 1, "operation": "set", "session": "s1", "expected_revision":None, "revision":"r1", "policy": policy},
                {"id": 2, "operation": "remove", "session": "s1", "expected_revision":"r1"},
                {"id": 3, "operation": "set", "session": "s2", "expected_revision":None, "revision":"r2", "policy": policy},
            ]
            result = subprocess.run([sys.executable, str(worker), root],
                                    input="".join(json.dumps(message) + "\n" for message in messages),
                                    capture_output=True, text=True, timeout=10, check=True)
            replies = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual([reply["id"] for reply in replies], [None, 1, 2, 3])
            self.assertTrue(all(reply["ok"] for reply in replies))
            self.assertFalse((Path(root) / "amaterasu/frame-limiter/active.json").exists())

    def test_invalid_json_does_not_replay_a_previous_request_id(self):
        with tempfile.TemporaryDirectory(prefix="amaterasu-limiter-worker-") as root:
            worker = Path(__file__).with_name("worker.py")
            result = subprocess.run([sys.executable, str(worker), root],
                                    input='{"id":1,"operation":"remove","session":"s","expected_revision":"r1"}\n{broken\n',
                                    capture_output=True, text=True, timeout=10, check=True)
            replies = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual([reply["id"] for reply in replies], [None, 1, None])
            self.assertFalse(replies[-1]["ok"])

    def test_replayed_operation_is_stable_and_changed_payload_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="amaterasu-limiter-worker-") as root:
            worker = Path(__file__).with_name("worker.py")
            first = {"id": 1, "operation": "remove", "session": "one", "expected_revision":"r1"}
            conflicting = {"id": 1, "operation": "remove", "session": "two", "expected_revision":"r1"}
            messages = [first, first, conflicting]
            result = subprocess.run([sys.executable, str(worker), root],
                                    input="".join(json.dumps(message) + "\n" for message in messages),
                                    capture_output=True, text=True, timeout=10, check=True)
            replies = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(replies[1], replies[2])
            self.assertEqual(replies[3]["error"], "operation_id_conflict")

    def test_hidden_runtime_file_uses_live_peer_and_stops_after_worker_exit(self):
        with tempfile.TemporaryDirectory(prefix="amaterasu-relay-") as root:
            process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("worker.py")), root],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(self.read_reply(process)["state"], "ready")
                policy = {"app_id": "42", "provider": "mangohud-proton", "limit_millihz": 60000,
                          "preset": "custom", "method": "late", "graph": True}
                process.stdin.write(json.dumps({"id": 1, "operation": "set", "session": "s",
                    "expected_revision": None, "revision": "r1", "policy": policy}) + "\n")
                process.stdin.flush()
                self.assertEqual(self.read_reply(process)["state"], "stored")
                self.assertEqual(amaterasu_limiter._request_policy(root, "42"), policy)
                self.assertIsNone(amaterasu_limiter._request_policy(root, "99"))
                environment = {"XDG_RUNTIME_DIR": root, "SteamAppId": "42"}
                with mock.patch.object(amaterasu_limiter, "_load_policy", side_effect=FileNotFoundError):
                    self.assertTrue(amaterasu_limiter.apply({"g_session": types.SimpleNamespace(env=environment)}))
                self.assertEqual(environment["MANGOHUD"], "1")
                self.assertIn("frame_timing=1", environment["MANGOHUD_CONFIG"])
                process.stdin.close()
                process.wait(timeout=5)
                with self.assertRaises(OSError):
                    amaterasu_limiter._request_policy(root, "42")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                if not process.stdin.closed:
                    process.stdin.close()
                process.stdout.close()
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()
