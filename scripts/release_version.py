"""Version rules shared by release asset and Homebrew tooling."""

import re


TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-beta\.(0|[1-9][0-9]*))?\Z")


def version_key(tag: str) -> tuple[int, int, int, int, int]:
    match = TAG.fullmatch(tag)
    if not match:
        raise ValueError(f"invalid release tag: {tag}")
    major, minor, patch, beta = match.groups()
    return int(major), int(minor), int(patch), int(beta is None), int(beta or 0)


def is_prerelease(tag: str) -> bool:
    return version_key(tag)[3] == 0


def should_update_formula(current: str, new: str) -> bool:
    old_key, new_key = version_key(current), version_key(new)
    # Once the tap has a stable release it remains on the stable channel.
    if old_key[3] != new_key[3]:
        return new_key[3] > old_key[3]
    return new_key >= old_key
