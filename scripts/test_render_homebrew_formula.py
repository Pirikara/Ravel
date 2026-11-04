import importlib.util
from pathlib import Path
import unittest


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


if __name__ == "__main__":
    unittest.main()
