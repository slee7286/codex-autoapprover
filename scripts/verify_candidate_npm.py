#!/usr/bin/env python3
"""Check candidate npm lock and installed package identities; never certify support."""

import argparse
import hashlib
import json
from pathlib import Path
import platform

from npm_candidate import strict_json_object, verify_installed, verify_lock
from verify_candidate_asset import load_candidate, require_recorded_candidate_matches_official


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--recorded-candidate", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--installed-root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    official = load_candidate(args.candidate)
    require_recorded_candidate_matches_official(official, load_candidate(args.recorded_candidate))
    if args.lock.is_symlink() or not args.lock.is_file() or args.lock.stat().st_size > 1024 * 1024:
        raise ValueError("npm candidate lock must be a bounded regular file")
    lock_body = args.lock.read_bytes()
    lock = json.loads(lock_body, object_pairs_hook=strict_json_object)
    native = verify_lock(lock, official, args.version, platform.system())
    if args.installed_root:
        verify_installed(args.installed_root, args.version, platform.system())
    if args.output:
        args.output.write_text(json.dumps({
            "schema_version": 1, "codex_version": args.version, "os": platform.system(),
            "lock_sha256": hashlib.sha256(lock_body).hexdigest(),
            "native_package": native, "installed": args.installed_root is not None,
            "status": "npm-registry-integrity-only", "certified": False,
        }, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
