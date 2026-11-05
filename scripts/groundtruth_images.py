#!/usr/bin/env python3
"""Compare locally cached images with package managers running inside them.

This opt-in check never pulls an image. Run it on the same Docker platform used
to capture the saved Syft and Trivy outputs when using --compare-saved.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


IMAGES = (
    ("nginx", "nginx:alpine"),
    ("redis", "redis:7-alpine"),
    ("python", "python:3.13-slim"),
)


def run(command):
    completed = subprocess.run(command, capture_output=True, text=True, check=True, timeout=180)
    return completed.stdout.strip()


def in_image(image, entrypoint, *args):
    return run(["docker", "run", "--rm", "--network", "none", "--memory", "512m", "--cpus", "2",
                "--entrypoint", entrypoint, image, *args])


def count(gold, actual):
    matched = sum((gold & actual).values())
    return {
        "expected": sum(gold.values()),
        "emitted": sum(actual.values()),
        "matched": matched,
        "missing": [str(x) for x in sorted((gold - actual).elements())],
        "extra": [str(x) for x in sorted((actual - gold).elements())],
    }


def image_reference(image):
    [info] = json.loads(run(["docker", "image", "inspect", image]))
    return {"tag": image, "image_id": info["Id"], "architecture": info["Architecture"]}


def references(label, image):
    result = {}
    if label in ("nginx", "redis"):
        installed = in_image(image, "apk", "--no-network", "info", "-v")
        result["apk"] = Counter(installed.splitlines())
    if label == "redis":
        version = re.search(r"\bv=([^ ]+)", in_image(image, "redis-server", "--version"))
        if not version:
            raise ValueError("redis-server did not report a version")
        result["runtime"] = Counter({("redis", version.group(1)): 1})
    if label == "python":
        installed = in_image(image, "dpkg-query", "-W", "-f=${Package}\t${Version}\n")
        result["deb"] = Counter(tuple(line.split("\t", 1)) for line in installed.splitlines())
        result["pypi"] = Counter(
            (package["name"].casefold(), package["version"])
            for package in json.loads(in_image(image, "python", "-m", "pip", "list", "--format=json"))
        )
        vendor = in_image(image, "python", "-c",
                          "import pathlib, pip._vendor; print(pathlib.Path(pip._vendor.__file__).with_name('vendor.txt').read_text())")
        result["vendor"] = Counter(
            (name.strip().casefold(), version.strip())
            for line in vendor.splitlines() if "==" in line
            for name, version in [line.split("==", 1)]
        )
        version = re.fullmatch(r"Python ([^ ]+)", in_image(image, "python", "--version"))
        if not version:
            raise ValueError("python did not report a version")
        result["runtime"] = Counter({("python", version.group(1)): 1})
    return result


def ravel_components(binary, image):
    with tempfile.TemporaryDirectory(prefix="ravel-image-groundtruth-") as directory:
        output = Path(directory) / "sbom.json"
        run([binary, "scan", image, "--image-source", "docker", "--format", "ravel-json",
             "--output", str(output)])
        return json.loads(output.read_text())["components"]


def ravel_inventory(components, scope):
    collectors = {
        "apk": {"apk-installed", "apk-installed-adb"},
        "deb": {"dpkg-status"},
        "pypi": {"python-dist-info", "python-egg-info"},
        "vendor": {"pip-vendor"},
        "runtime": {"redis-runtime-elf", "python-runtime-elf"},
    }[scope]
    selected = [c for c in components if any(e.get("collector") in collectors for e in c.get("evidence", []))]
    if scope == "apk":
        return Counter(c["name"] + "-" + c["version"] for c in selected)
    if scope in ("pypi", "vendor"):
        return Counter((c["name"].casefold(), c["version"]) for c in selected)
    return Counter((c["name"], c["version"]) for c in selected)


def saved_tool_inventory(path, scope, reference):
    components = json.loads(path.read_text()).get("components", [])
    if scope in ("apk", "deb"):
        prefix = "pkg:apk/" if scope == "apk" else "pkg:deb/"
        selected = [c for c in components if c.get("purl", "").startswith(prefix)]
        if scope == "apk":
            return Counter(c["name"] + "-" + c["version"] for c in selected)
        return Counter((c["name"], c["version"]) for c in selected)
    if scope in ("pypi", "vendor"):
        selected = [c for c in components if c.get("purl", "").startswith("pkg:pypi/")]
        available = Counter((c["name"].casefold(), c["version"]) for c in selected)
        # pip list and pip's vendor.txt describe different populations.
        return available & reference
    if scope == "runtime":
        available = Counter((c.get("name", ""), c.get("version", "")) for c in components
                            if c.get("type") not in ("file", "operating-system"))
        return available & reference
    raise ValueError(scope)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ravel", required=True, help="freshly built Ravel binary")
    parser.add_argument("--compare-saved", action="store_true", help="score existing Syft/Trivy image SBOMs")
    parser.add_argument("--saved-dir", default="comparison/groundtruth-images")
    args = parser.parse_args()
    saved_manifest = None
    if args.compare_saved:
        saved_manifest = json.loads((Path(args.saved_dir) / "manifest.json").read_text())
    results = []
    for label, image in IMAGES:
        reference = image_reference(image)
        if saved_manifest is not None:
            saved = saved_manifest[label]
            if saved["image_id"] != reference["image_id"] or saved["architecture"] != reference["architecture"]:
                raise ValueError(f"saved {label} SBOMs belong to a different image or architecture")
            for tool in ("syft", "trivy"):
                saved_sbom = Path(args.saved_dir) / f"{label}-{tool}.cdx.json"
                digest = hashlib.sha256(saved_sbom.read_bytes()).hexdigest()
                if digest != saved[f"{tool}_sbom_sha256"]:
                    raise ValueError(f"saved {label} {tool} SBOM changed")
        gold = references(label, image)
        components = ravel_components(args.ravel, image)
        checks = {}
        for scope, expected in gold.items():
            scores = {"ravel": count(expected, ravel_inventory(components, scope))}
            if scope in ("apk", "deb"):
                evidence_collectors = {"apk-installed", "apk-installed-adb"} if scope == "apk" else {"dpkg-status"}
                scores["ravel"]["purl_claims"] = sum(
                    bool(c.get("purl")) for c in components
                    if any(e.get("collector") in evidence_collectors for e in c.get("evidence", []))
                )
            if args.compare_saved:
                for tool in ("syft", "trivy"):
                    scores[tool] = count(expected, saved_tool_inventory(
                        Path(args.saved_dir) / f"{label}-{tool}.cdx.json", scope, expected))
                    if scope in ("apk", "deb"):
                        scores[tool]["purl_claims"] = scores[tool]["emitted"]
            checks[scope] = scores
        results.append({"image": reference, "checks": checks})
    print(json.dumps(results, ensure_ascii=False, indent=2))
    if any(item["checks"][scope]["ravel"]["missing"] or item["checks"][scope]["ravel"]["extra"]
           for item in results for scope in item["checks"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
