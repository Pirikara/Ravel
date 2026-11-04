#!/usr/bin/env python3
"""Check published GitHub Release asset metadata against local build outputs."""

import argparse
import hashlib
import json
from pathlib import Path
import re


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TARGETS = ("linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64", "windows_amd64")


def verify(tag: str, checksum_bytes: bytes, metadata: dict, allow_draft: bool = False) -> None:
    lines = [line.split() for line in checksum_bytes.decode().splitlines()]
    if len(lines) != 5 or any(len(line) != 2 for line in lines):
        raise ValueError("SHA256SUMS must contain five archives")
    expected = {name: digest for digest, name in lines}
    names = {f"ravel_{tag}_{target}.{'zip' if target.startswith('windows') else 'tar.gz'}" for target in TARGETS}
    if set(expected) != names or not all(SHA256.fullmatch(digest) for digest in expected.values()):
        raise ValueError("invalid or duplicate checksum entries")
    if (metadata.get("isDraft") and not allow_draft) or not metadata.get("isPrerelease"):
        raise ValueError("release is not a published prerelease")
    assets = metadata.get("assets", [])
    if len(assets) != 6 or {asset.get("name") for asset in assets} != set(expected) | {"SHA256SUMS"}:
        raise ValueError("release assets differ from expected archives")
    expected["SHA256SUMS"] = hashlib.sha256(checksum_bytes).hexdigest()
    for asset in assets:
        if asset.get("digest") != "sha256:" + expected[asset["name"]] or asset.get("size", 0) <= 0:
            raise ValueError(f"release asset digest or size mismatch: {asset['name']}")
        if asset["name"] != "SHA256SUMS" and not asset["name"].startswith(f"ravel_{tag}_"):
            raise ValueError(f"release asset belongs to a different tag: {asset['name']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    parser.add_argument("checksums", type=Path)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("--allow-draft", action="store_true")
    args = parser.parse_args()
    verify(args.tag, args.checksums.read_bytes(), json.loads(args.metadata.read_text()), args.allow_draft)


if __name__ == "__main__":
    main()
