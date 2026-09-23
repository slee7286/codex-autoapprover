#!/usr/bin/env python3
"""Verify the pinned repair CLI before a dedicated repair key is supplied."""

import argparse
import json
from pathlib import Path
import platform

from npm_candidate import (PACKAGE, fetch_npm_records, stable_version,
                           strict_json_object, verify_installed, verify_lock)


MAX_LOCK_BYTES = 1024 * 1024


def read_json_file(path, limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("repair CLI metadata must be a bounded regular file")
    return json.loads(path.read_bytes(), object_pairs_hook=strict_json_object)


def verify(root, *, installed=False, system=None, records=None):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("repair CLI root must be a plain directory")
    package = read_json_file(root / "package.json", 4096)
    if (not isinstance(package, dict)
            or set(package) != {"name", "version", "private", "dependencies"}
            or package["name"] != "codex-autoapprover-repair-cli"
            or package["version"] != "0.0.0"
            or package["private"] is not True
            or not isinstance(package["dependencies"], dict)
            or set(package["dependencies"]) != {PACKAGE}):
        raise ValueError("repair CLI package manifest differs from the pinned shape")
    version = package["dependencies"][PACKAGE]
    stable_version(version)
    lock = read_json_file(root / "package-lock.json", MAX_LOCK_BYTES)
    packages = lock.get("packages") if isinstance(lock, dict) else None
    if (not isinstance(packages, dict)
            or lock.get("name") != package["name"]
            or lock.get("version") != package["version"]
            or packages.get("") != {
                "name": package["name"], "version": package["version"],
                "dependencies": {PACKAGE: version},
            }):
        raise ValueError("repair CLI lock root differs from its package manifest")
    records = records if records is not None else fetch_npm_records(version)
    system = system or platform.system()
    verify_lock(lock, {"codex_version": version, "npm_packages": records}, version, system)
    if installed:
        verify_installed(root, version, system)
    return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args()
    version = verify(args.root, installed=args.installed)
    print(f"Pinned Codex {version} repair CLI integrity verified; no compatibility certified")


if __name__ == "__main__":
    main()
