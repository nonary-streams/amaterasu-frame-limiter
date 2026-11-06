import os
import hashlib
from pathlib import Path
import runpy
import stat
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

import amaterasu_limiter
import install_hook


class HookInstallationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="amaterasu-proton-fixture-")
        self.addCleanup(self.directory.cleanup)
        self.tool = Path(self.directory.name)
        (self.tool / "proton").write_text("fixture", encoding="utf-8")
        (self.tool / "user_settings.sample.py").write_text("user_settings = {}\n", encoding="utf-8")
        self.helper = Path(install_hook.__file__).with_name("amaterasu_limiter.py").read_bytes()

    def test_existing_settings_survive_and_installation_is_idempotent(self):
        settings = self.tool / "user_settings.py"
        previous = b"user_settings = {'CUSTOM': 'value'}\n"
        settings.write_bytes(previous)
        settings.chmod(0o640)
        install_hook.install(self.tool, self.helper)
        result = settings.read_bytes()
        self.assertTrue(result.startswith(previous))
        self.assertEqual(stat.S_IMODE(settings.stat().st_mode), 0o640)
        compile(result, str(settings), "exec")
        install_hook.install(self.tool, self.helper)
        self.assertEqual(settings.read_bytes(), result)
        self.assertEqual((self.tool / install_hook._HELPER).read_bytes(), self.helper)

    def test_missing_settings_create_private_valid_file(self):
        install_hook.install(self.tool, self.helper)
        settings = self.tool / "user_settings.py"
        self.assertEqual(stat.S_IMODE(settings.stat().st_mode), 0o600)
        compile(settings.read_bytes(), str(settings), "exec")

    def test_installed_hook_applies_only_while_owner_state_is_live(self):
        install_hook.install(self.tool, self.helper)
        runtime = self.tool / "runtime"
        state_dir = runtime / "amaterasu" / "frame-limiter"
        state_dir.mkdir(parents=True)
        state_path = state_dir / "active.json"
        state = {"version": 1, "owner": {"pid": os.getpid(),
                 "start_ticks": amaterasu_limiter._process_start(os.getpid()),
                 "expires_unix_ms": time.time_ns() // 1_000_000 + 60000},
                 "policies": [{"app_id": None, "provider": "proton", "limit_millihz": 59940,
                               "preset": "custom", "method": "late", "graph": False}]}
        import json
        state_path.write_text(json.dumps(state), encoding="utf-8")
        state_path.chmod(0o600)
        main = sys.modules["__main__"]
        previous = getattr(main, "g_session", None)
        session = types.SimpleNamespace(env={"XDG_RUNTIME_DIR": str(runtime), "DXVK_FRAME_RATE": "30"})
        main.g_session = session
        try:
            namespace = runpy.run_path(str(self.tool / "user_settings.py"))
            self.assertEqual(session.env["VKD3D_FRAME_RATE"], "59.94")
            self.assertEqual(namespace["user_settings"]["DXVK_FRAME_RATE"], "60")
            state_path.unlink()
            session.env = {"XDG_RUNTIME_DIR": str(runtime), "DXVK_FRAME_RATE": "30"}
            runpy.run_path(str(self.tool / "user_settings.py"))
            self.assertEqual(session.env["DXVK_FRAME_RATE"], "30")
        finally:
            if previous is None:
                del main.g_session
            else:
                main.g_session = previous

    def test_foreign_helper_and_modified_hook_are_preserved(self):
        helper = self.tool / install_hook._HELPER
        helper.write_text("different", encoding="utf-8")
        with self.assertRaises(ValueError):
            install_hook.install(self.tool, self.helper)
        self.assertEqual(helper.read_text(encoding="utf-8"), "different")
        helper.unlink()
        settings = self.tool / "user_settings.py"
        damaged = b"user_settings = {}\n# BEGIN Amaterasu frame limiter v1\n"
        settings.write_bytes(damaged)
        with self.assertRaises(ValueError):
            install_hook.install(self.tool, self.helper)
        self.assertEqual(settings.read_bytes(), damaged)

    def test_symlink_and_hardlink_settings_are_refused(self):
        external = self.tool / "external"
        external.write_text("user_settings = {}\n", encoding="utf-8")
        settings = self.tool / "user_settings.py"
        settings.symlink_to(external)
        with self.assertRaises(OSError):
            install_hook.install(self.tool, self.helper)
        settings.unlink()
        os.link(external, settings)
        with self.assertRaises(ValueError):
            install_hook.install(self.tool, self.helper)
        self.assertEqual(external.read_text(encoding="utf-8"), "user_settings = {}\n")

    def test_invalid_existing_python_is_not_overwritten(self):
        settings = self.tool / "user_settings.py"
        settings.write_text("invalid python =\n", encoding="utf-8")
        with self.assertRaises(SyntaxError):
            install_hook.install(self.tool, self.helper)
        self.assertEqual(settings.read_text(encoding="utf-8"), "invalid python =\n")

    def test_only_recognized_previous_helper_is_upgraded_with_permissions_preserved(self):
        helper = self.tool / install_hook._HELPER
        previous = b"# exact previous packaged helper\n"
        helper.write_bytes(previous)
        helper.chmod(0o640)
        with mock.patch.object(install_hook, "_PREVIOUS_HELPERS", {hashlib.sha256(previous).hexdigest()}):
            install_hook.install(self.tool, self.helper)
        self.assertEqual(helper.read_bytes(), self.helper)
        self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o640)
        helper.write_bytes(self.helper + b"# external edit\n")
        with self.assertRaises(ValueError):
            install_hook.install(self.tool, self.helper)


if __name__ == "__main__":
    unittest.main()
