import hashlib
import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("verify-release-assets.py")
SPEC = importlib.util.spec_from_file_location("verify_release_assets", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class VerifyReleaseAssetsTests(unittest.TestCase):
    def test_matching_release(self):
        tag = "v0.1.0-beta.4"
        entries = [("a" * 64, f"ravel_{tag}_{target}.{'zip' if target.startswith('windows') else 'tar.gz'}") for target in MODULE.TARGETS]
        checksums = "".join(f"{digest}  {name}\n" for digest, name in entries).encode()
        assets = [{"name": name, "digest": "sha256:" + digest, "size": 42} for digest, name in entries]
        assets.append({"name": "SHA256SUMS", "digest": "sha256:" + hashlib.sha256(checksums).hexdigest(), "size": len(checksums)})
        metadata = {"isDraft": False, "isPrerelease": True, "assets": assets}
        MODULE.verify(tag, checksums, metadata)
        metadata["isDraft"] = True
        with self.assertRaises(ValueError):
            MODULE.verify(tag, checksums, metadata)
        MODULE.verify(tag, checksums, metadata, allow_draft=True)
        metadata["isDraft"] = False
        metadata["assets"][0]["digest"] = "sha256:" + "b" * 64
        with self.assertRaises(ValueError):
            MODULE.verify(tag, checksums, metadata)


if __name__ == "__main__":
    unittest.main()
