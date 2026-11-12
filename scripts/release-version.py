#!/usr/bin/env python3
"""Fail unless every crate of this module carries the version being released."""

import json
from pathlib import Path
import re
import sys


def package_field(manifest, field):
    """A string field of [package], read without a TOML parser: Cargo
    accepts newer TOML syntax than Python's parser does."""
    table = re.search(r"(?ms)^\[package\][ \t]*$(.*?)(?=^\[|\Z)", manifest)
    match = table and re.search(rf'(?m)^{re.escape(field)}[ \t]*=[ \t]*"([^"]*)"[ \t]*$', table.group(1))
    return match.group(1) if match else None


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: release-version.py VERSION")
    expected = sys.argv[1]
    repository = Path(__file__).resolve().parents[1]
    module = json.loads((repository / "metadata" / "module.json").read_text(encoding="utf-8"))
    wrong = []
    for component in module["components"]:
        manifest = repository / component.get("path", ".") / "Cargo.toml"
        version = package_field(manifest.read_text(encoding="utf-8"), "version")
        if version != expected:
            wrong.append(f"{component['package']} is {version!r}")
    if wrong:
        sys.exit(f"tag names version {expected}, but " + ", ".join(wrong))
    print(f"all {len(module['components'])} crate(s) are at {expected}")


if __name__ == "__main__":
    main()
