import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from release_version import is_prerelease, should_update_formula, version_key

SCRIPT = Path(__file__).with_name("render-homebrew-formula.py")
SPEC = importlib.util.spec_from_file_location("render_homebrew_formula", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RenderHomebrewFormulaTests(unittest.TestCase):
    def setUp(self):
        self.tag = "v0.1.0-beta.4"
        self.checksums = "".join(
            f"{'a' * 64}  ravel_{self.tag}_{target}.{'zip' if target.startswith('windows') else 'tar.gz'}\n"
            for target in MODULE.TARGETS
        )
        self.template = Path(__file__).resolve().parents[1] / "packaging" / "homebrew" / "ravel.rb.in"

    def test_render_contains_release_and_checksums(self):
        formula = MODULE.render(self.tag, self.checksums, self.template.read_text())
        self.assertIn('version "0.1.0-beta.4"', formula)
        self.assertEqual(formula.count('sha256 "' + 'a' * 64 + '"'), 4)
        self.assertIn('ravel_v0.1.0-beta.4_darwin_arm64.tar.gz', formula)

    def test_missing_archive_is_rejected(self):
        lines = self.checksums.splitlines()
        with self.assertRaises(ValueError):
            MODULE.render(self.tag, "\n".join(lines[:-1]), self.template.read_text())

    def test_duplicate_archive_is_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.render(self.tag, self.checksums + self.checksums.splitlines()[0] + "\n", self.template.read_text())

    def test_stable_formula(self):
        formula = MODULE.render("v0.1.0", self.checksums.replace(self.tag, "v0.1.0"), self.template.read_text())
        self.assertIn('version "0.1.0"', formula)
        self.assertIn('ravel_v0.1.0_linux_arm64.tar.gz', formula)

    def test_tap_preserves_stable_and_newer_releases(self):
        for current, new, expected in [
            ("v0.1.0-beta.45", "v0.1.0", True),
            ("v0.1.0", "v0.2.0-beta.1", False),
            ("v0.1.1", "v0.1.0", False),
            ("v0.1.0-beta.10", "v0.1.0-beta.9", False),
            ("v0.1.0-beta.9", "v0.1.0-beta.10", True),
            ("v0.1.0", "v0.1.0", True),
            ("v0.1.0", "v0.1.1", True),
        ]:
            with self.subTest(current=current, new=new):
                self.assertEqual(should_update_formula(current, new), expected)

    def test_update_existing_formula_through_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, sums = root / "ravel.rb", root / "SHA256SUMS"
            stable = MODULE.render("v0.1.0", self.checksums.replace(self.tag, "v0.1.0"), self.template.read_text())
            output.write_text(stable)
            for tag, expected in [("v0.2.0-beta.1", stable), ("v0.1.1", None)]:
                sums.write_text(self.checksums.replace(self.tag, tag))
                subprocess.run([sys.executable, str(SCRIPT), tag, str(sums), str(output), "--update-existing"], check=True, capture_output=True)
                if expected is not None:
                    self.assertEqual(output.read_text(), expected)
                else:
                    self.assertIn('version "0.1.1"', output.read_text())

    def test_only_canonical_stable_and_beta_tags(self):
        self.assertFalse(is_prerelease("v0.1.0"))
        self.assertTrue(is_prerelease("v0.2.0-beta.1"))
        for tag in ["0.1.0", "v01.0.0", "v0.1.0-beta.01", "v0.1.0-rc.1", "v0.1.0+build", "v0.1.0\n"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                version_key(tag)


if __name__ == "__main__":
    unittest.main()
