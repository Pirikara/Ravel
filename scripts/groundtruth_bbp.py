#!/usr/bin/env python3
"""Check selected BBP snapshots against their package-manager lock records.

The snapshots live under the ignored comparison/ directory. This is a
lock-record check, not a claim about what was installed in a built artifact.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib


CASES = {
    "notion-npm": ("npm", "package-lock.json"),
    "cargo-vercel-axum": ("cargo", "Cargo.lock"),
    "composer-wordpress-plugin": ("composer", "composer.lock"),
    "nuget-bitwarden": ("nuget", "packages.lock.json"),
    "swift-stripe": ("swift", "Package.resolved"),
}


def key(name, version, manager):
    if manager == "nuget":  # NuGet IDs are case-insensitive.
        name = name.casefold()
    return (name, version or "")


def expected_packages(manager, path):
    if manager == "cargo":
        lock = tomllib.loads(path.read_text())
        root = tomllib.loads((path.parent / "Cargo.toml").read_text())["package"]["name"]
        return Counter(
            key(p["name"], p["version"], manager)
            for p in lock["package"]
            if p.get("source") or p["name"] != root
        )
    lock = json.loads(path.read_text())
    if manager == "npm":
        return Counter(
            key(p.get("name") or location.rsplit("node_modules/", 1)[-1], p["version"], manager)
            for location, p in lock["packages"].items()
            if location
        )
    if manager == "composer":
        return Counter(
            key(p["name"], p["version"], manager)
            for p in lock["packages"] + lock.get("packages-dev", [])
        )
    if manager == "nuget":
        # This sample has one target framework. Keep each lock entry once.
        [packages] = lock["dependencies"].values()
        return Counter(
            key(name, record.get("resolved", ""), manager)
            for name, record in packages.items()
        )
    if manager == "swift":
        pins = lock.get("pins", lock.get("object", {}).get("pins", []))
        return Counter(
            key(pin["identity"], pin["state"].get("version", ""), manager)
            for pin in pins
        )
    raise ValueError(manager)


def expected_origins(manager, path):
    if manager == "nuget":
        return None  # packages.lock.json does not declare a registry URL.
    if manager == "cargo":
        lock = tomllib.loads(path.read_text())
        return Counter(
            (key(p["name"], p["version"], manager), "declared_registry", p["source"].removeprefix("registry+"), "")
            for p in lock["package"]
            if p.get("source", "").startswith("registry+")
        )
    lock = json.loads(path.read_text())
    if manager == "npm":
        return Counter(
            (key(p.get("name") or location.rsplit("node_modules/", 1)[-1], p["version"], manager),
             "download_url", p["resolved"], "")
            for location, p in lock["packages"].items()
            if location and p.get("resolved", "").startswith("https://registry.npmjs.org/")
        )
    if manager == "composer":
        result = Counter()
        for p in lock["packages"] + lock.get("packages-dev", []):
            identity = key(p["name"], p["version"], manager)
            if p.get("dist", {}).get("url"):
                result[(identity, "download_url", p["dist"]["url"], "")] += 1
            if p.get("source", {}).get("url"):
                result[(identity, "vcs", p["source"]["url"], "")] += 1
        return result
    if manager == "swift":
        pins = lock.get("pins", lock.get("object", {}).get("pins", []))
        return Counter(
            (key(pin["identity"], pin["state"].get("version", ""), manager),
             "vcs", pin["location"], pin["state"].get("revision", ""))
            for pin in pins
        )
    raise ValueError(manager)


def scan(binary, snapshot):
    with tempfile.TemporaryDirectory(prefix="ravel-groundtruth-") as temp:
        output = Path(temp) / "sbom.json"
        subprocess.run(
            [binary, "scan", str(snapshot), "--all", "--format", "ravel-json", "--output", str(output)],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(output.read_text())


def evaluate(binary, audit_dir):
    results = []
    binary_digest = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    for name, (manager, filename) in CASES.items():
        snapshot = audit_dir / name / "snapshot"
        lock = snapshot / filename
        if not lock.is_file():
            raise FileNotFoundError(lock)
        gold = expected_packages(manager, lock)
        doc = scan(binary, snapshot)
        actual = Counter(
            key(p["name"], p.get("version", ""), manager)
            for p in doc["components"]
            if p["kind"] in ("package", "application")
        )
        matched = sum((gold & actual).values())
        missing = sorted((gold - actual).elements())
        extra = sorted((actual - gold).elements())
        result = {
            "sample": name,
            "manager": manager,
            "reference": f"{name}/snapshot/{filename}",
            "reference_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
            "ravel_sha256": binary_digest,
            "scan_options": ["--all", "--format", "ravel-json"],
            "expected": sum(gold.values()),
            "emitted": sum(actual.values()),
            "matched": matched,
            "precision": matched / sum(actual.values()) if actual else 1.0,
            "recall": matched / sum(gold.values()) if gold else 1.0,
            "missing": [f"{n}@{v}" for n, v in missing],
            "extra": [f"{n}@{v}" for n, v in extra],
        }
        gold_origins = expected_origins(manager, lock)
        if gold_origins is not None:
            by_id = {p["id"]: key(p["name"], p.get("version", ""), manager)
                     for p in doc["components"]}
            actual_origins = Counter()
            for origin in doc.get("origins", []):
                identity = by_id.get(origin["occurrence"])
                if identity is None:
                    continue
                kind = origin["kind"]
                url = origin.get("safeUrl", "")
                if manager == "npm" and (kind != "download_url" or not url.startswith("https://registry.npmjs.org/")):
                    continue
                if manager == "cargo" and kind != "declared_registry":
                    continue
                if manager == "composer" and kind not in ("download_url", "vcs"):
                    continue
                if manager == "swift" and kind != "vcs":
                    continue
                revision = origin.get("revision", "") if manager == "swift" else ""
                actual_origins[(identity, kind, url, revision)] += 1
            match_origins = sum((gold_origins & actual_origins).values())
            result["origin_expected"] = sum(gold_origins.values())
            result["origin_emitted"] = sum(actual_origins.values())
            result["origin_matched"] = match_origins
            result["origin_missing"] = [str(x) for x in sorted((gold_origins - actual_origins).elements())]
            result["origin_extra"] = [str(x) for x in sorted((actual_origins - gold_origins).elements())]
        results.append(result)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ravel", required=True, help="freshly built Ravel binary")
    parser.add_argument("--audit-dir", default="comparison/bbp-audit")
    args = parser.parse_args()
    results = evaluate(args.ravel, Path(args.audit_dir))
    print(json.dumps(results, ensure_ascii=False, indent=2))
    if any(item["missing"] or item["extra"] or item.get("origin_missing") or item.get("origin_extra") for item in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
