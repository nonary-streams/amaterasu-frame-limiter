#!/usr/bin/env python3
"""Build this independent plugin against an explicitly selected SDK checkout."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("sdk_root", type=Path)
parser.add_argument("--test", action="store_true")
parser.add_argument("--clippy", action="store_true")
parser.add_argument("--release", action="store_true")
args = parser.parse_args()
repository = Path(__file__).resolve().parents[1]
sdk_root = args.sdk_root.resolve(strict=True)
if not (sdk_root / "crates/module-sdk/Cargo.toml").is_file():
    parser.error("The selected checkout does not contain the Amaterasu SDK")
if not os.environ.get("CARGO_TARGET_DIR"):
    parser.error("Set CARGO_TARGET_DIR to the intended build volume")
target = Path(os.environ["CARGO_TARGET_DIR"]).resolve()
target.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="amaterasu-plugin-manifest-", dir=target) as temporary:
    workspace = Path(temporary)
    manifest = (repository / "Cargo.toml").read_text()
    manifest = manifest.replace("[lib]", "[workspace]\n\n[lib]\npath = " + json.dumps(str(repository / "src/lib.rs")))
    for dependency in ["module-sdk", "configuration-schema"]:
        manifest = re.sub(r'path = "[^"\n]*crates/' + dependency + r'"',
                          'path = ' + json.dumps(str(sdk_root / "crates" / dependency)), manifest)
    (workspace / "Cargo.toml").write_text(manifest)
    operation = "test" if args.test else "clippy" if args.clippy else "build"
    command = ["cargo", operation, "--manifest-path", str(workspace / "Cargo.toml")]
    if args.release:
        command += ["--release"]
    if args.clippy:
        command += ["--all-targets", "--", "-D", "warnings"]
    subprocess.run(command, check=True)
