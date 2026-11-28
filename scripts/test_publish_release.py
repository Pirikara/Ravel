import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
COMMIT = "a" * 40


class PublishReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in ("scripts", "dist", "bin", "docs/releases"):
            (self.root / name).mkdir(parents=True)
        for name in ("publish-release.sh", "verify-release-assets.py", "release_version.py"):
            shutil.copy(SCRIPTS / name, self.root / "scripts" / name)
        self.env = {**os.environ, "PATH": str(self.root / "bin") + os.pathsep + os.environ["PATH"]}
        self.stub("git", """
import sys
args=sys.argv[1:]
if args[0]=='rev-parse': print('a'*40)
elif args[0]=='describe': print('v0.0.9')
elif args[0]!='fetch': raise SystemExit('unexpected git arguments: '+str(args))
""")
        self.stub("gh", """
import json,sys
from pathlib import Path
a=sys.argv[1:];p=Path('state.json')
with Path('calls.jsonl').open('a') as f:f.write(json.dumps(a)+'\\n')
if a[:2]==['release','view']:
 if not p.exists():raise SystemExit(1)
 d=json.loads(p.read_text())
 if '--jq' in a:print(json.dumps(d['isDraft']))
 else:print(json.dumps(d))
elif a[:2]==['release','create']:
 d=json.loads(Path('expected.json').read_text());p.write_text(json.dumps(d))
elif a[:2]==['release','upload']:pass
elif a[:2]==['release','edit']:
 d=json.loads(p.read_text());d['isDraft']=False
 d['isPrerelease']='--prerelease=true' in a;p.write_text(json.dumps(d))
else:raise SystemExit('unexpected gh arguments: '+str(a))
""")

    def stub(self, name, code):
        path = self.root / "bin" / name
        path.write_text(f"#!{sys.executable}\n" + code)
        path.chmod(0o755)

    def assets(self, tag):
        for file in (self.root / "dist").iterdir():
            file.unlink()
        lines, assets = [], []
        for target in ("linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64", "windows_amd64"):
            name = f"ravel_{tag}_{target}.{'zip' if target.startswith('windows') else 'tar.gz'}"
            data = name.encode()
            (self.root / "dist" / name).write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            lines.append(f"{digest}  {name}\n")
            assets.append({"name": name, "digest": "sha256:" + digest, "size": len(data)})
        checksums = "".join(lines).encode()
        (self.root / "dist/SHA256SUMS").write_bytes(checksums)
        assets.append({"name": "SHA256SUMS", "digest": "sha256:" + hashlib.sha256(checksums).hexdigest(), "size": len(checksums)})
        metadata = {"isDraft": False, "isPrerelease": "-beta." in tag, "assets": assets}
        (self.root / "expected.json").write_text(json.dumps(metadata))
        return metadata

    def run_publish(self, tag):
        result = subprocess.run(["bash", "scripts/publish-release.sh", tag, COMMIT], cwd=self.root, env=self.env, capture_output=True, text=True, timeout=15)
        log = self.root / "calls.jsonl"
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, calls

    def test_stable_release_uses_notes_and_latest(self):
        tag = "v0.1.0"
        self.assets(tag)
        (self.root / f"docs/releases/{tag}.md").write_text("First stable release\n")
        result, calls = self.run_publish(tag)
        self.assertEqual(result.returncode, 0, result.stderr)
        create = next(c for c in calls if c[:2] == ["release", "create"])
        self.assertIn("--prerelease=false", create)
        self.assertIn("--latest=true", create)
        self.assertIn("--notes-file", create)
        self.assertNotIn("--generate-notes", create)

    def test_beta_release_stays_prerelease(self):
        self.assets("v0.2.0-beta.1")
        result, calls = self.run_publish("v0.2.0-beta.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        create = next(c for c in calls if c[:2] == ["release", "create"])
        self.assertIn("--prerelease=true", create)
        self.assertIn("--latest=false", create)
        self.assertIn("--generate-notes", create)
        self.assertEqual(create[create.index("--notes-start-tag") + 1], "v0.0.9")

    def test_draft_resume_preserves_release_channel(self):
        for tag in ["v0.1.0", "v0.2.0-beta.1"]:
            with self.subTest(tag=tag):
                metadata = self.assets(tag)
                metadata["isDraft"] = True
                (self.root / "state.json").write_text(json.dumps(metadata))
                (self.root / "calls.jsonl").unlink(missing_ok=True)
                result, calls = self.run_publish(tag)
                self.assertEqual(result.returncode, 0, result.stderr)
                edit = next(c for c in calls if c[:2] == ["release", "edit"])
                self.assertIn("--prerelease=" + str("-beta." in tag).lower(), edit)
                self.assertIn("--latest=" + str("-beta." not in tag).lower(), edit)

    def test_published_asset_mismatch_is_not_overwritten(self):
        metadata = self.assets("v0.1.0")
        metadata["assets"][0]["digest"] = "sha256:" + "b" * 64
        (self.root / "state.json").write_text(json.dumps(metadata))
        result, calls = self.run_publish("v0.1.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all(c[:2] == ["release", "view"] for c in calls))

    def test_published_matching_release_is_reusable(self):
        metadata = self.assets("v0.1.0")
        (self.root / "state.json").write_text(json.dumps(metadata))
        result, calls = self.run_publish("v0.1.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(c[:2] == ["release", "view"] for c in calls))


if __name__ == "__main__":
    unittest.main()
