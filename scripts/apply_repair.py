#!/usr/bin/env python3
"""Apply a bounded untrusted repair patch in a separate trusted workflow job."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from repair_candidate import (MAX_CHANGED_FILES, MAX_PATCH_BYTES, allowed_repair_path,
                              clean_base, collect_patch, validate_candidate)
from verify_candidate_asset import load_candidate
from watch_codex import version_key


REPORT_FIELDS = {"schema_version", "codex_version", "base_sha", "upstream_source_sha", "changed_paths",
                 "patch_sha256", "checks", "status", "certified"}


def patch_paths(repo, path):
    output = subprocess.check_output(["git", "apply", "--numstat", "-z", str(path)], cwd=repo)
    paths = []
    for row in output.split(b"\0"):
        if not row:
            continue
        fields = row.split(b"\t", 2)
        if len(fields) != 3 or not fields[2]:
            raise ValueError("repair patch uses an unsupported rename or path")
        name = fields[2].decode("utf-8")
        if not allowed_repair_path(name):
            raise ValueError("repair patch changes a forbidden path")
        paths.append(name)
    if not paths or len(paths) > MAX_CHANGED_FILES or len(set(paths)) != len(paths):
        raise ValueError("repair patch has no files, duplicate files or too many files")
    return sorted(paths)


def apply(repo, patch_path, report, version):
    version_key(version)
    if (not isinstance(report, dict) or set(report) != REPORT_FIELDS
            or type(report["schema_version"]) is not int or report["schema_version"] != 1
            or report["codex_version"] != version or report["status"] != "proposed-unverified"
            or report["certified"] is not False
            or report["checks"] != ["format", "rust-tests", "clippy"]
            or not isinstance(report["base_sha"], str)
            or re.fullmatch(r"[0-9a-f]{40}", report["base_sha"]) is None
            or not isinstance(report["upstream_source_sha"], str)
            or re.fullmatch(r"[0-9a-f]{40}", report["upstream_source_sha"]) is None
            or not isinstance(report["patch_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", report["patch_sha256"]) is None):
        raise ValueError("invalid bounded repair report")
    base = clean_base(repo)
    if base != report["base_sha"]:
        raise ValueError("candidate branch changed after the repair attempt")
    candidate = load_candidate(repo / "compatibility" / "candidate.json")
    if validate_candidate(candidate) != version or candidate["upstream_source_sha"] != report["upstream_source_sha"]:
        raise ValueError("repair report source differs from the pinned candidate")
    patch = patch_path.read_bytes()
    if not patch or len(patch) > MAX_PATCH_BYTES or hashlib.sha256(patch).hexdigest() != report["patch_sha256"]:
        raise ValueError("repair patch integrity failed")
    paths = patch_paths(repo, patch_path)
    if report["changed_paths"] != paths:
        raise ValueError("repair report paths do not match the patch")
    subprocess.run(["git", "apply", "--check", str(patch_path)], cwd=repo, check=True)
    subprocess.run(["git", "apply", str(patch_path)], cwd=repo, check=True)
    actual, _ = collect_patch(repo, base)
    if actual != paths:
        raise ValueError("applied repair paths differ from the reviewed patch")
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--patch", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    paths = apply(args.repo.resolve(), args.patch.resolve(), report, args.version)
    print(f"Applied {len(paths)} bounded Rust files for review; compatibility remains unverified")


if __name__ == "__main__":
    main()
