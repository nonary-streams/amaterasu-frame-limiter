import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest

import amaterasu_limiter as limiter


class ProtonPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="amaterasu-limiter-test-")
        self.addCleanup(self.directory.cleanup)
        self.state_path = Path(self.directory.name) / "active.json"
        self.policy = {"app_id": None, "provider": "proton", "limit_millihz": 59940,
                       "preset": "custom", "method": "late", "graph": False}
        self.state = {"version": 1, "owner": {"pid": os.getpid(),
                      "start_ticks": limiter._process_start(os.getpid()),
                      "expires_unix_ms": time.time_ns() // 1_000_000 + 60_000},
                      "policies": [self.policy]}
        self.write_state()

    def write_state(self):
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
        self.state_path.chmod(0o600)

    def run_hook(self, env=None, settings=None):
        session = types.SimpleNamespace(env=dict(env or {}))
        namespace = {"g_session": session, "user_settings": dict(settings or {})}
        result = limiter.apply(namespace, self.state_path)
        return result, session.env, namespace["user_settings"]

    def test_proton_overrides_stale_options_with_expected_units(self):
        applied, env, settings = self.run_hook(
            {"DXVK_FRAME_RATE": "30", "DXVK_CONFIG": "dxgi.maxFrameRate = 30",
             "LD_PRELOAD": f"/opt/lib.so:{limiter._SHIM}", "MANGOHUD": "1"},
            {"DXVK_FRAME_RATE": "31"},
        )
        self.assertTrue(applied)
        self.assertEqual(env["VKD3D_FRAME_RATE"], "59.94")
        self.assertEqual(env["DXVK_FRAME_RATE"], "60")
        self.assertTrue(env["DXVK_CONFIG"].endswith("d3d9.maxFrameRate = 60"))
        self.assertEqual(settings["DXVK_FRAME_RATE"], "60")
        self.assertEqual(env["LD_PRELOAD"], "/opt/lib.so")
        self.assertNotIn("MANGOHUD", env)

    def test_mangohud_fractional_limit_and_existing_configuration(self):
        self.policy.update(provider="mangohud", preset="3", graph=True, method="early")
        self.write_state()
        applied, env, _ = self.run_hook({"MANGOHUD_CONFIG": "fps_limit=25", "MANGOHUD_FPS_LIMIT": "25"})
        self.assertTrue(applied)
        self.assertTrue(env["MANGOHUD_CONFIG"].endswith("fps_limit_method=early,fps_limit=59.94"))
        self.assertNotIn("MANGOHUD_FPS_LIMIT", env)
        self.assertEqual(env["LD_PRELOAD"], limiter._SHIM)

    def test_overlay_does_not_add_a_second_limiter(self):
        self.policy["provider"] = "mangohud-proton"
        self.write_state()
        applied, env, _ = self.run_hook()
        self.assertTrue(applied)
        self.assertTrue(env["MANGOHUD_CONFIG"].endswith("fps_limit=0"))
        self.assertEqual(env["VKD3D_FRAME_RATE"], "59.94")

    def test_expired_or_reused_owner_and_unsafe_state_are_inert(self):
        for key, value in (("expires_unix_ms", 1), ("start_ticks", 1)):
            old = self.state["owner"][key]
            self.state["owner"][key] = value
            self.write_state()
            applied, env, _ = self.run_hook({"UNCHANGED": "yes"})
            self.assertFalse(applied)
            self.assertEqual(env, {"UNCHANGED": "yes"})
            self.state["owner"][key] = old
        self.write_state()
        self.state_path.chmod(0o666)
        self.assertFalse(self.run_hook()[0])
        self.state_path.unlink()
        self.state_path.symlink_to(Path(self.directory.name) / "target")
        self.assertFalse(self.run_hook()[0])

    def test_application_policy_wins_and_ambiguous_global_policies_are_inert(self):
        app_policy = dict(self.policy, app_id="42", provider="mangohud")
        self.state["policies"].append(app_policy)
        self.write_state()
        self.assertIn("MANGOHUD_CONFIG", self.run_hook({"SteamAppId": "42"})[1])
        self.state["policies"].append(dict(self.policy))
        self.write_state()
        self.assertTrue(self.run_hook({"SteamAppId": "99"})[0])
        self.state["policies"][-1]["limit_millihz"] = 120000
        self.write_state()
        self.assertFalse(self.run_hook({"SteamAppId": "99"})[0])

    def test_container_manifest_uses_visible_host_libraries_and_preserves_other_layers(self):
        host = Path(self.directory.name) / "host"
        manifests = host / "usr/share/vulkan/implicit_layer.d"
        library = host / "usr/lib/mangohud"
        manifests.mkdir(parents=True)
        library.mkdir(parents=True)
        (library / "libMangoHud.so").write_bytes(b"fixture")
        (library / "libMangoHud_shim.so").write_bytes(b"\x7fELF\x02")
        (manifests / "MangoHud.x86_64.json").write_text(json.dumps({"layer": {
            "name": "VK_LAYER_MANGOHUD_overlay_x86_64", "library_path": "/usr/lib/mangohud/libMangoHud.so"}}))
        policy = dict(self.policy, provider="mangohud-proton", graph=True)
        inherited = {"VK_IMPLICIT_LAYER_PATH": "/other/layers", "LD_PRELOAD": "/other/preload.so"}
        changes = limiter._container_overlay(limiter._edits(policy, inherited), inherited, host, self.directory.name)
        self.assertTrue(changes["VK_IMPLICIT_LAYER_PATH"].endswith(":/other/layers"))
        generated = Path(changes["VK_IMPLICIT_LAYER_PATH"].split(":")[0]) / "MangoHud.x86_64.json"
        self.assertEqual(json.loads(generated.read_text())["layer"]["library_path"], str(library / "libMangoHud.so"))
        self.assertTrue(changes["LD_PRELOAD"].startswith("/other/preload.so:"))
        self.assertIn("frame_timing=1", changes["MANGOHUD_CONFIG"])


if __name__ == "__main__":
    unittest.main()
