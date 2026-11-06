from pathlib import Path
import tempfile
import unittest

import discovery


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="amaterasu-steam-fixture-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "steam"
        self.library = Path(self.directory.name) / 'library "two"'
        (self.root / "steamapps").mkdir(parents=True)
        self.common = self.library / "steamapps" / "common"
        self.common.mkdir(parents=True)

    @staticmethod
    def tool(directory):
        directory.mkdir(parents=True)
        (directory / "proton").write_text("fixture", encoding="utf-8")
        (directory / "user_settings.sample.py").write_text("user_settings = {}", encoding="utf-8")

    def test_finds_user_tools_in_library_and_compatibility_directory(self):
        tool = self.common / "Proton 11"
        other = self.root / "compatibilitytools.d" / "GE-Proton"
        self.tool(tool)
        self.tool(other)
        escaped = str(self.library).replace("\\", "\\\\").replace('"', '\\"')
        (self.root / "steamapps" / "libraryfolders.vdf").write_text(
            f'// library list\n"libraryfolders" {{ "0" {{ "path" "{escaped}" "apps" {{ "42" "1" }} }} }}',
            encoding="utf-8")
        (self.common / "symlink").symlink_to(tool)
        found, diagnostics = discovery.discover([str(self.root)])
        self.assertEqual(found, sorted([str(tool), str(other)]))
        self.assertEqual(diagnostics, [])

    def test_invalid_library_list_is_reported_without_mutating_anything(self):
        (self.root / "steamapps" / "libraryfolders.vdf").write_text('"libraryfolders" {', encoding="utf-8")
        found, diagnostics = discovery.discover([str(self.root)])
        self.assertEqual(found, [])
        self.assertEqual(diagnostics, ["library_list_unavailable"])

    def test_duplicate_vdf_keys_and_unbounded_roots_are_rejected(self):
        with self.assertRaises(ValueError):
            discovery._document('"a" "1" "a" "2"')
        with self.assertRaises(ValueError):
            discovery.discover(["relative"])
        with self.assertRaises(ValueError):
            discovery.discover([str(self.root)] * 65)


if __name__ == "__main__":
    unittest.main()
