#!/usr/bin/env python3
"""Build this module against an explicit SDK checkout.

The module's manifests inherit package fields, dependencies and lints from the
workspace that contains them, and reach shared crates by relative path. The
host repository mounts this repository inside its workspace; a standalone build
has to offer the same surroundings. This stages a throwaway workspace under
CARGO_TARGET_DIR: a copy of the SDK checkout as the root, and a copy of this
repository at the path the host mounts it. Neither checkout is modified, and no
manifest or source path is rewritten.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

# Never staged: version control, the SDK checkout CI places here, and build output.
SKIPPED_NAMES = {".git", ".sdk", "target", "node_modules", "__pycache__"}
STAGE_DIRECTORY = "standalone-workspace"


def read_module(repository):
    """The module's own description: where it mounts and which crates it builds."""
    with (repository / "metadata" / "module.json").open("rb") as source:
        module = json.load(source)
    mount = module.get("mount")
    components = module.get("components")
    if module.get("schema") != 1 or not isinstance(mount, str) or not isinstance(components, list) or not components:
        raise ValueError("metadata/module.json must declare schema 1, a mount path and its components")
    mount_parts = Path(mount).parts
    if Path(mount).is_absolute() or not mount_parts or any(part in ("..", ".") for part in mount_parts):
        raise ValueError("the mount path must be relative and stay inside the workspace")
    crates = []
    for component in components:
        path = component.get("path", ".")
        package = component.get("package")
        if not isinstance(path, str) or not isinstance(package, str) or not package:
            raise ValueError("each component needs a crate path and a package name")
        if Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("a component path must stay inside this repository")
        manifest = repository / path / "Cargo.toml"
        declared = package_field(manifest.read_text(encoding="utf-8"), "name")
        if declared != package:
            raise ValueError(f"{manifest} declares {declared!r}, not {package!r}")
        crates.append((Path(path), package))
    for extra in module.get("workspace_members", []):
        if not isinstance(extra, str) or Path(extra).is_absolute() or ".." in Path(extra).parts:
            raise ValueError("workspace_members must be paths inside this repository")
        crates.append((Path(extra), None))
    return Path(mount), crates


def package_field(manifest, field):
    """A string field of a manifest's [package] table.

    Read with a pattern rather than a TOML parser: Cargo accepts newer TOML
    syntax than Python's parser does, and a crate manifest may use it.
    """
    table = re.search(r"(?ms)^\[package\][ \t]*$(.*?)(?=^\[|\Z)", manifest)
    match = table and re.search(rf'(?m)^{re.escape(field)}[ \t]*=[ \t]*"([^"]*)"[ \t]*$', table.group(1))
    return match.group(1) if match else None


def mirror(source, destination, skip=lambda relative: False):
    """Make `destination` hold exactly the files under `source`.

    Unchanged files keep their modification time, so Cargo does not rebuild a
    crate whose sources did not change between runs.
    """
    wanted = set()
    for directory, names, files in os.walk(source):
        relative_directory = Path(directory).relative_to(source)
        names[:] = [
            name for name in names
            if name not in SKIPPED_NAMES and not skip(relative_directory / name)
        ]
        (destination / relative_directory).mkdir(parents=True, exist_ok=True)
        for name in files:
            relative = relative_directory / name
            if name in SKIPPED_NAMES or skip(relative):
                continue
            wanted.add(relative)
            original = source / relative
            copy = destination / relative
            before = original.stat()
            if copy.is_file() and not copy.is_symlink():
                after = copy.stat()
                if after.st_size == before.st_size and after.st_mtime_ns == before.st_mtime_ns:
                    continue
            if copy.is_symlink() or copy.is_dir():
                remove(copy)
            shutil.copy2(original, copy)
    for directory, names, files in os.walk(destination, topdown=False):
        relative_directory = Path(directory).relative_to(destination)
        if skip(relative_directory) and relative_directory != Path("."):
            continue
        for name in files:
            relative = relative_directory / name
            if relative not in wanted and not skip(relative):
                (destination / relative).unlink()
        for name in names:
            child = destination / relative_directory / name
            if not skip(relative_directory / name) and child.is_dir() and not any(child.iterdir()):
                child.rmdir()


def remove(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def workspace_manifest(sdk_manifest, members):
    """The SDK's root manifest with this module's crates added as members."""
    parsed = tomllib.loads(sdk_manifest)
    existing = parsed.get("workspace", {}).get("members")
    if not isinstance(existing, list):
        raise ValueError("the SDK root manifest does not list workspace members")
    combined = existing + [member for member in members if member not in existing]
    listing = "members = [\n" + "".join(f"    {json.dumps(member)},\n" for member in combined) + "]"
    staged, replaced = re.subn(r"(?ms)^members\s*=\s*\[.*?^\]", lambda _: listing, sdk_manifest, count=1)
    if replaced != 1 or tomllib.loads(staged).get("workspace", {}).get("members") != combined:
        raise ValueError("could not add this module to the SDK workspace members")
    return staged


def stage(repository, sdk_root, target, mount, crates):
    workspace = target / STAGE_DIRECTORY
    workspace.mkdir(parents=True, exist_ok=True)
    generated = {Path("Cargo.toml"), Path("Cargo.lock")}

    def beside_sdk(relative):
        return relative in generated or relative == mount or mount in relative.parents

    mirror(sdk_root, workspace, skip=beside_sdk)
    mirror(repository, workspace / mount, skip=lambda relative: relative == Path("Cargo.lock"))
    members = [(mount / path).as_posix() for path, _ in crates]
    manifest = workspace_manifest((sdk_root / "Cargo.toml").read_text(encoding="utf-8"), members)
    manifest_path = workspace / "Cargo.toml"
    if not manifest_path.is_file() or manifest_path.read_text(encoding="utf-8") != manifest:
        manifest_path.write_text(manifest, encoding="utf-8")
    return workspace


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sdk_root", type=Path, help="Amaterasu SDK checkout at the revision named by sdk-revision")
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--test", action="store_true", help="run the module's tests")
    operation.add_argument("--clippy", action="store_true", help="check all targets with warnings denied")
    operation.add_argument("--fmt", action="store_true", help="check Rust formatting without modifying files")
    operation.add_argument("--update-lock", action="store_true", help="resolve dependencies and save Cargo.lock in this repository")
    parser.add_argument("--release", action="store_true", help="use Cargo's release profile")
    parser.add_argument("--offline", action="store_true", help="use only cached Cargo dependencies")
    parser.add_argument("--package", action="append", default=[], help="limit the run to one of this module's packages")
    parser.add_argument("--features", default="", help="comma-separated Cargo features to enable")
    parser.add_argument("--artifacts", type=Path, help="copy the built libraries into this directory")
    args = parser.parse_args()
    if args.release and (args.fmt or args.update_lock):
        parser.error("--release does not apply to this operation")
    if args.artifacts and (args.test or args.clippy or args.fmt or args.update_lock):
        parser.error("--artifacts applies to a build")
    if not os.environ.get("CARGO_TARGET_DIR"):
        parser.error("set CARGO_TARGET_DIR to the intended build volume")
    repository = Path(__file__).resolve().parents[1]
    try:
        sdk_root = args.sdk_root.resolve(strict=True)
        if not (sdk_root / "crates" / "module-sdk" / "Cargo.toml").is_file():
            raise ValueError(f"SDK source missing: {sdk_root / 'crates' / 'module-sdk'}")
        mount, crates = read_module(repository)
        packages = [package for _, package in crates if package]
        unknown = [name for name in args.package if name not in packages]
        if unknown:
            raise ValueError(f"not a package of this module: {', '.join(unknown)}")
        target = Path(os.environ["CARGO_TARGET_DIR"]).resolve()
        target.mkdir(parents=True, exist_ok=True)
        if repository in target.parents or target == repository:
            if target.relative_to(repository).parts[0] not in SKIPPED_NAMES:
                raise ValueError("CARGO_TARGET_DIR inside this repository must be its target directory")
        workspace = stage(repository, sdk_root, target, mount, crates)
    except (OSError, ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError) as error:
        parser.error(str(error))

    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(target)
    manifest = ["--manifest-path", str(workspace / "Cargo.toml")]
    saved_lock = repository / "Cargo.lock"
    staged_lock = workspace / "Cargo.lock"
    selected = args.package or packages

    if args.update_lock:
        # Start from the SDK's own resolution so shared crates keep the
        # versions the SDK was validated with.
        seed = saved_lock if saved_lock.is_file() else sdk_root / "Cargo.lock"
        if seed.is_file():
            shutil.copyfile(seed, staged_lock)
        result = subprocess.run(["cargo", "metadata", "--format-version", "1", *manifest],
                                env=environment, stdout=subprocess.DEVNULL, check=False)
        if result.returncode == 0:
            shutil.copyfile(staged_lock, saved_lock)
        return result.returncode

    locked = saved_lock.is_file()
    if locked:
        shutil.copyfile(saved_lock, staged_lock)
    elif (sdk_root / "Cargo.lock").is_file() and not staged_lock.is_file():
        shutil.copyfile(sdk_root / "Cargo.lock", staged_lock)

    if args.fmt:
        command = ["cargo", "fmt", *manifest]
        for package in selected:
            command.extend(["--package", package])
        command.extend(["--", "--check"])
    else:
        action = "test" if args.test else "clippy" if args.clippy else "build"
        command = ["cargo", action, *manifest]
        for package in selected:
            command.extend(["--package", package])
        if locked:
            command.append("--locked")
        if args.release:
            command.append("--release")
        if args.offline:
            command.append("--offline")
        if args.features:
            command.extend(["--features", args.features])
        if args.clippy:
            command.extend(["--all-targets", "--", "-D", "warnings"])
    result = subprocess.run(command, env=environment, check=False)
    if result.returncode != 0 or not args.artifacts:
        return result.returncode

    profile = target / ("release" if args.release else "debug")
    prefix, suffix = (
        ("", ".dll") if sys.platform == "win32" else ("lib", ".dylib") if sys.platform == "darwin" else ("lib", ".so")
    )
    args.artifacts.mkdir(parents=True, exist_ok=True)
    for package in selected:
        library = f"{prefix}{package.replace('-', '_')}{suffix}"
        built = profile / library
        if not built.is_file():
            print(f"build did not produce {built}", file=sys.stderr)
            return 1
        shutil.copyfile(built, args.artifacts / library)
        print(args.artifacts / library)
    return 0


if __name__ == "__main__":
    sys.exit(main())
