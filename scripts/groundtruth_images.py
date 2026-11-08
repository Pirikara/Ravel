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
from urllib.parse import unquote


IMAGES = (
    ("nginx", "nginx:alpine"),
    ("redis", "redis:7-alpine"),
    ("python", "python:3.13-slim"),
    ("ruby", "ruby:3.3.10-slim"),
    ("conda", "continuumio/miniconda3:latest"),
    ("node", "node:24-bookworm-slim"),
    ("phpmyadmin", "phpmyadmin:latest"),
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
    if label == "ruby":
        installed = in_image(image, "ruby", "-rrubygems", "-rjson", "-e",
                             "puts JSON.generate(Gem::Specification.map { |s| [s.name, s.version.to_s, s.platform.to_s] })")
        gems = json.loads(installed)
        result["gem"] = Counter((name, version) for name, version, _ in gems)
        version = re.match(r"ruby ([^ ]+)", in_image(image, "ruby", "--version"))
        if not version:
            raise ValueError("ruby did not report a version")
        result["runtime"] = Counter({("ruby", version.group(1)): 1})
    if label == "conda":
        installed = json.loads(in_image(image, "conda", "list", "--json"))
        result["conda"] = Counter((package["name"], package["version"]) for package in installed)
        result["conda_builds"] = Counter(
            (package["name"], package["version"], package["build_string"]) for package in installed
        )
        explicit = in_image(image, "conda", "list", "--explicit")
        result["conda_urls"] = Counter(line for line in explicit.splitlines() if line.startswith("https://"))
    if label == "node":
        tree = json.loads(in_image(image, "npm", "ls", "--global", "--all", "--json"))
        def installed_coordinates(node):
            for name, package in node.get("dependencies", {}).items():
                if "version" in package:
                    yield name, package["version"]
                yield from installed_coordinates(package)
        # npm ls repeats a physical package when multiple dependencies reach it.
        result["npm"] = Counter(set(installed_coordinates(tree)))
        paths = in_image(image, "npm", "ls", "--global", "--all", "--parseable")
        result["npm_paths"] = Counter(
            line.lstrip("/") for line in paths.splitlines()
            if line.startswith("/usr/local/lib/node_modules/")
        )
        result["runtime"] = Counter({("node", in_image(image, "node", "--version").removeprefix("v")): 1})
    if label == "phpmyadmin":
        records = json.loads(in_image(
            image, "php", "-r",
            'require "/var/www/html/vendor/autoload.php"; echo json_encode(Composer\\InstalledVersions::getAllRawData(), JSON_UNESCAPED_SLASHES);',
        ))
        # Composer can register the same installed.php twice. Virtual provides
        # have no pretty_version, and the root application is not a dependency.
        result["composer"] = Counter({
            (name, package["pretty_version"])
            for record in records for name, package in record["versions"].items()
            if "pretty_version" in package and name != record["root"]["name"]
        })
        version = re.match(r"PHP ([^ ]+)", in_image(image, "php", "--version"))
        if not version:
            raise ValueError("PHP did not report a version")
        result["runtime"] = Counter({("php-cli", version.group(1)): 1})
    return result


def ravel_document(binary, image):
    with tempfile.TemporaryDirectory(prefix="ravel-image-groundtruth-") as directory:
        output = Path(directory) / "sbom.json"
        run([binary, "scan", image, "--image-source", "docker", "--format", "ravel-json",
             "--output", str(output)])
        return json.loads(output.read_text())


def ravel_conda_urls(document):
    conda_ids = {c["id"] for c in document["components"] if any(
        e.get("collector") == "conda-meta" for e in c.get("evidence", []))}
    return Counter(origin["safeUrl"] for origin in document["origins"]
                   if origin["occurrence"] in conda_ids and origin["kind"] == "download_url"
                   and origin["status"] == "recorded_in_install_metadata")


def ravel_inventory(components, scope):
    collectors = {
        "apk": {"apk-installed", "apk-installed-adb"},
        "deb": {"dpkg-status"},
        "pypi": {"python-dist-info", "python-egg-info"},
        "vendor": {"pip-vendor"},
        "gem": {"ruby-installed-gemspec"},
        "conda": {"conda-meta"},
        "npm": {"node-package-json"},
        "npm_paths": {"node-package-json"},
        "composer": {"composer-installed"},
        "runtime": {"redis-runtime-elf", "python-runtime-elf", "ruby-runtime-elf", "node-runtime-elf", "php-cli-elf"},
    }[scope]
    selected = [c for c in components if any(e.get("collector") in collectors for e in c.get("evidence", []))]
    if scope in ("npm", "npm_paths"):
        selected = [c for c in selected if c.get("context", "").startswith("location=usr/local/lib/node_modules/")]
        if scope == "npm_paths":
            return Counter(c["context"].split("location=", 1)[1].split(";", 1)[0] for c in selected)
    if scope == "apk":
        return Counter(c["name"] + "-" + c["version"] for c in selected)
    if scope in ("pypi", "vendor"):
        return Counter((c["name"].casefold(), c["version"]) for c in selected)
    return Counter((c["name"], c["version"]) for c in selected)


def ravel_conda_builds(components):
    selected = [c for c in components if any(e.get("collector") == "conda-meta"
                for e in c.get("evidence", []))]
    builds = []
    for component in selected:
        fields = dict(field.split("=", 1) for field in component.get("context", "").split(";") if "=" in field)
        if "build" in fields:
            builds.append((component["name"], component["version"], fields["build"]))
    return Counter(builds)


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
    if scope in ("gem", "conda"):
        selected = [c for c in components if c.get("purl", "").startswith("pkg:" + scope + "/")]
        return Counter((c["name"], c["version"]) for c in selected)
    if scope == "npm":
        selected = [c for c in components if c.get("purl", "").startswith("pkg:npm/")]
        # Some CycloneDX writers put the npm scope only in the PURL.
        return Counter({(unquote(c["purl"][8:].split("?", 1)[0].rsplit("@", 1)[0]), c["version"])
                        for c in selected})
    if scope == "composer":
        selected = [c for c in components if c.get("purl", "").startswith("pkg:composer/")]
        return Counter((c["name"], c["version"]) for c in selected)
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
        document = ravel_document(args.ravel, image)
        components = document["components"]
        checks = {}
        for scope, expected in gold.items():
            if scope == "conda_builds":
                continue
            if scope == "conda_urls":
                checks[scope] = {"ravel": count(expected, ravel_conda_urls(document))}
                continue
            scores = {"ravel": count(expected, ravel_inventory(components, scope))}
            if scope == "conda":
                scores["ravel"]["build_matched"] = sum(
                    (gold["conda_builds"] & ravel_conda_builds(components)).values()
                )
                scores["ravel"]["build_expected"] = sum(gold["conda_builds"].values())
            if scope in ("apk", "deb"):
                evidence_collectors = {"apk-installed", "apk-installed-adb"} if scope == "apk" else {"dpkg-status"}
                scores["ravel"]["purl_claims"] = sum(
                    bool(c.get("purl")) for c in components
                    if any(e.get("collector") in evidence_collectors for e in c.get("evidence", []))
                )
            if args.compare_saved and scope != "npm_paths":
                for tool in ("syft", "trivy"):
                    scores[tool] = count(expected, saved_tool_inventory(
                        Path(args.saved_dir) / f"{label}-{tool}.cdx.json", scope, expected))
                    if scope == "conda":
                        saved_components = json.loads((Path(args.saved_dir) / f"{label}-{tool}.cdx.json").read_text()).get("components", [])
                        py_names = Counter((c["name"], c["version"]) for c in saved_components
                                           if c.get("purl", "").startswith("pkg:pypi/"))
                        scores[tool]["pypi_name_version_overlap"] = sum((expected & py_names).values())
                    if scope in ("apk", "deb"):
                        scores[tool]["purl_claims"] = scores[tool]["emitted"]
            checks[scope] = scores
        results.append({"image": reference, "checks": checks})
    print(json.dumps(results, ensure_ascii=False, indent=2))
    if any(item["checks"][scope]["ravel"]["missing"] or item["checks"][scope]["ravel"]["extra"] or
           (scope == "conda" and item["checks"][scope]["ravel"]["build_matched"] !=
            item["checks"][scope]["ravel"]["build_expected"])
           for item in results for scope in item["checks"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
