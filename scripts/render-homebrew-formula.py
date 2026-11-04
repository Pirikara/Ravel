#!/usr/bin/env python3
"""Render the Homebrew formula from a verified Ravel release checksum file."""

import argparse
from pathlib import Path
import re
from string import Template


TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TARGETS = ("darwin_arm64", "darwin_amd64", "linux_arm64", "linux_amd64", "windows_amd64")


def render(tag: str, checksum_text: str, template_text: str) -> str:
    if not TAG.fullmatch(tag):
        raise ValueError(f"invalid release tag: {tag}")
    expected = {f"ravel_{tag}_{target}.{'zip' if target.startswith('windows') else 'tar.gz'}" for target in TARGETS}
    sums: dict[str, str] = {}
    for line in checksum_text.splitlines():
        fields = line.split()
        if len(fields) != 2 or not SHA256.fullmatch(fields[0]) or fields[1] in sums:
            raise ValueError(f"invalid or duplicate checksum entry: {line}")
        sums[fields[1]] = fields[0]
    if set(sums) != expected:
        raise ValueError(f"checksum entries differ from expected release archives: {set(sums) ^ expected}")
    values = {"TAG": tag, "VERSION": tag.removeprefix("v")}
    for target in TARGETS:
        if target.startswith("windows"):
            continue
        values[target.upper()] = sums[f"ravel_{tag}_{target}.tar.gz"]
    return Template(template_text).substitute(values)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("tag")
    parser.add_argument("checksums", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    template = Path(__file__).resolve().parents[1] / "packaging" / "homebrew" / "ravel.rb.in"
    result = render(args.tag, args.checksums.read_text(), template.read_text())
    args.output.write_text(result)


if __name__ == "__main__":
    main()
