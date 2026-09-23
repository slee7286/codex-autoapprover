#!/usr/bin/env python3
"""Compare a candidate binary with two independent offline builds of HEAD.

This is a native build observation, not proof of upstream source provenance or
approval-hook compatibility. The archive is extracted without links or traversal.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

from release_gate import load_json, source_digest


MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 2048
MAX_FILE_BYTES = 16 * 1024 * 1024
BINARY_NAME = "codex-autoapprover.exe" if os.name == "nt" else "codex-autoapprover"
SOURCE_ROOT = Path(__file__).resolve().parents[1]
REPORT_FIELDS = {
    "schema_version", "status", "git_commit", "host", "rustc", "cargo",
    "source_archive_sha256", "source_sha256", "expected_binary_sha256",
    "independent_build_sha256", "byte_identical",
}


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_output(*args):
    return subprocess.check_output(["git", *args], cwd=SOURCE_ROOT, text=True).strip()


def archive_head(destination):
    with destination.open("xb") as stream:
        subprocess.run(["git", "archive", "--format=tar", "HEAD"],
                       cwd=SOURCE_ROOT, check=True, stdout=stream)
    if destination.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("source archive exceeds the reproducibility limit")


def safe_member_name(member):
    name = member.name.rstrip("/")
    path = PurePosixPath(name)
    if (not name or name.startswith("/") or "\\" in name or ":" in name
            or any(part in ("", ".", "..") for part in name.split("/"))
            or path.as_posix() != name or not (member.isfile() or member.isdir())
            or member.size > MAX_FILE_BYTES):
        raise ValueError("source archive has an unsafe entry")
    return path


def extract_archive(archive, root):
    with tarfile.open(archive, "r:") as bundle:
        members = bundle.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ValueError("source archive has too many entries")
        names = set()
        checked = []
        for member in members:
            path = safe_member_name(member)
            folded = str(path).casefold()
            if folded in names:
                raise ValueError("source archive has duplicate or case-colliding entries")
            names.add(folded)
            checked.append((member, path))
        for member, relative in checked:
            destination = root.joinpath(*relative.parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError("source archive file has no body")
                with source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output)
                if destination.stat().st_size != member.size:
                    raise ValueError("source archive file changed during extraction")
                destination.chmod(member.mode & 0o777)


def build_snapshot(source):
    environment = os.environ.copy()
    for key in ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER"):
        environment.pop(key, None)
    environment["CARGO_INCREMENTAL"] = "0"
    subprocess.run(["cargo", "build", "--release", "--offline", "--locked",
                    "--bin", "codex-autoapprover"],
                   cwd=source, env=environment, check=True)
    binary = source / "target" / "release" / BINARY_NAME
    if not binary.is_file():
        raise ValueError("native reproducibility build produced no executable")
    return digest_file(binary)


def check(binary, output):
    if not binary.is_file() or binary.is_symlink():
        raise ValueError("expected native binary must be a regular file")
    if git_output("status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("reproducibility check requires a clean Git tree")
    commit = git_output("rev-parse", "HEAD^{commit}")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("cannot resolve an exact source commit")
    expected = digest_file(binary)
    source_sha256 = source_digest(SOURCE_ROOT)
    with tempfile.TemporaryDirectory(prefix="codex-autoapprover-repro-") as temporary:
        root = Path(temporary)
        archive = root / "source.tar"
        archive_head(archive)
        archive_digest = digest_file(archive)
        built = []
        for label in ("first", "second"):
            source = root / label
            source.mkdir()
            extract_archive(archive, source)
            if source_digest(source) != source_sha256:
                raise ValueError("archived build source differs from the clean checkout")
            built.append(build_snapshot(source))
    report = {
        "schema_version": 1,
        "status": "unqualified-native-reproducibility-observation",
        "git_commit": commit,
        "host": sys.platform,
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "cargo": subprocess.check_output(["cargo", "--version"], text=True).strip(),
        "source_archive_sha256": archive_digest,
        "source_sha256": source_sha256,
        "expected_binary_sha256": expected,
        "independent_build_sha256": built,
        "byte_identical": expected == built[0] == built[1],
    }
    if output is not None:
        with output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    if not report["byte_identical"]:
        raise ValueError("candidate binary differs from one or both independent builds")


def verify_report(binary, path):
    if not binary.is_file() or binary.is_symlink():
        raise ValueError("expected native binary must be a regular file")
    if git_output("status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("reproducibility report verification requires a clean Git tree")
    if path.stat().st_size > 16 * 1024 or path.is_symlink():
        raise ValueError("reproducibility report is oversized or linked")
    report = load_json(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or set(report) != REPORT_FIELDS:
        raise ValueError("reproducibility report fields do not match schema 1")
    with tempfile.TemporaryDirectory(prefix="codex-autoapprover-repro-verify-") as temporary:
        archive = Path(temporary) / "source.tar"
        archive_head(archive)
        archive_digest = digest_file(archive)
    expected = digest_file(binary)
    digest = lambda value: isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
    if (type(report["schema_version"]) is not int or report["schema_version"] != 1
            or report["status"] != "unqualified-native-reproducibility-observation"
            or report["git_commit"] != git_output("rev-parse", "HEAD^{commit}")
            or report["host"] != sys.platform
            or report["rustc"] != subprocess.check_output(["rustc", "--version"], text=True).strip()
            or report["cargo"] != subprocess.check_output(["cargo", "--version"], text=True).strip()
            or not digest(report["source_archive_sha256"])
            or report["source_archive_sha256"] != archive_digest
            or not digest(report["source_sha256"])
            or report["source_sha256"] != source_digest(SOURCE_ROOT)
            or not digest(report["expected_binary_sha256"])
            or report["expected_binary_sha256"] != expected
            or not isinstance(report["independent_build_sha256"], list)
            or report["independent_build_sha256"] != [expected, expected]
            or report["byte_identical"] is not True):
        raise ValueError("reproducibility report differs from this source, toolchain or binary")
    print("reproducibility report matches the clean source, toolchain and binary")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--output", type=Path)
    mode.add_argument("--verify-report", type=Path)
    args = parser.parse_args()
    try:
        if args.verify_report is None:
            check(args.binary.absolute(), args.output)
        else:
            verify_report(args.binary.absolute(), args.verify_report)
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError,
            UnicodeError) as error:
        parser.exit(1, f"reproducibility check failed: {error}\n")


if __name__ == "__main__":
    main()
