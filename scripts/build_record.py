#!/usr/bin/env python3
"""Record bounded native build-host facts for an exact unqualified candidate.

This observation is review material, not reproducibility proof or provenance.
The protected workflow and independent review must establish how it was made.
"""

import argparse
import hashlib
import json
import platform
from pathlib import Path
import re
import subprocess

from binary_sbom import ROOT, checked_binary, native_target
from release_gate import load_json, source_digest


MAX_RECORD_BYTES = 16 * 1024
TARGET_SYSTEMS = {
    "x86_64-unknown-linux-gnu": "Linux",
    "x86_64-pc-windows-msvc": "Windows",
}
RECORD_FIELDS = {
    "schema_version", "status", "target", "binary_sha256", "source_sha256",
    "cargo_lock_sha256", "manifest_sha256", "git_commit", "git_tree_clean",
    "toolchain", "host",
}
HOST_FIELDS = {"system", "release", "version", "machine", "distribution_id", "distribution_version"}
TOOLCHAIN_FIELDS = {"rustc_verbose", "cargo_version"}


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def bounded_text(value: str, label: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(char) < 32 for char in value):
        raise ValueError(f"invalid {label}")
    return value


def bounded_tool_text(value: str, label: str, limit: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > limit \
            or any(ord(char) < 32 and char != "\n" for char in value):
        raise ValueError(f"invalid {label}")
    return value


def command_output(command: list[str], limit: int = 4096) -> str:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, check=True, timeout=10)
    if len(result.stdout) > limit or result.stderr:
        raise ValueError(f"unexpected tool output: {command[0]}")
    return bounded_tool_text(result.stdout.decode("utf-8").strip().replace("\r\n", "\n"), command[0], limit)


def git_identity() -> tuple[str, bool]:
    commit = command_output(["git", "rev-parse", "HEAD"], 64)
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise ValueError("invalid Git commit identity")
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=normal"],
                            cwd=ROOT, capture_output=True, check=True, timeout=10)
    if len(status.stdout) > 256 * 1024 or status.stderr:
        raise ValueError("cannot inspect build tree cleanliness")
    return commit, not status.stdout


def host_facts(target: str) -> dict:
    system = platform.system()
    if system != TARGET_SYSTEMS[target]:
        raise ValueError("build host differs from native target")
    distribution_id = distribution_version = "n/a"
    if system == "Linux":
        distribution = platform.freedesktop_os_release()
        distribution_id = distribution.get("ID", "unknown")
        distribution_version = distribution.get("VERSION_ID", "unknown")
    return {
        "system": bounded_text(system, "host system"),
        "release": bounded_text(platform.release(), "host release"),
        "version": bounded_text(platform.version(), "host version"),
        "machine": bounded_text(platform.machine(), "host machine"),
        "distribution_id": bounded_text(distribution_id, "distribution id"),
        "distribution_version": bounded_text(distribution_version, "distribution version"),
    }


def make_record(binary: Path, require_clean: bool) -> dict:
    target, _ = native_target()
    source_before = source_digest(ROOT)
    binary_before = sha256(checked_binary(binary, target))
    commit, clean = git_identity()
    if require_clean and not clean:
        raise ValueError("native build tree is dirty")
    rustc = command_output(["rustc", "-vV"])
    cargo = command_output(["cargo", "-V"])
    hosts = re.findall(r"(?m)^host: (\S+)$", rustc)
    if hosts != [target]:
        raise ValueError("recorded Rust host differs from binary target")
    record = {
        "schema_version": 1,
        "status": "unqualified-native-build-observation",
        "target": target,
        "binary_sha256": binary_before,
        "source_sha256": source_before,
        "cargo_lock_sha256": sha256((ROOT / "Cargo.lock").read_bytes()),
        "manifest_sha256": sha256((ROOT / "compatibility/manifest.json").read_bytes()),
        "git_commit": commit,
        "git_tree_clean": clean,
        "toolchain": {"rustc_verbose": rustc, "cargo_version": cargo},
        "host": host_facts(target),
    }
    if source_digest(ROOT) != source_before or sha256(checked_binary(binary, target)) != binary_before:
        raise ValueError("source or native binary changed while recording build facts")
    return record


def validate_record(record: dict, binary: Path, require_clean: bool) -> None:
    target, _ = native_target()
    if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
        raise ValueError("invalid native build record fields")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1 \
            or record["status"] != "unqualified-native-build-observation" or record["target"] != target:
        raise ValueError("invalid native build record identity")
    expected = {
        "binary_sha256": sha256(checked_binary(binary, target)),
        "source_sha256": source_digest(ROOT),
        "cargo_lock_sha256": sha256((ROOT / "Cargo.lock").read_bytes()),
        "manifest_sha256": sha256((ROOT / "compatibility/manifest.json").read_bytes()),
    }
    if any(record[key] != value for key, value in expected.items()):
        raise ValueError("native build record differs from binary or source")
    commit, clean = git_identity()
    if record["git_commit"] != commit or type(record["git_tree_clean"]) is not bool:
        raise ValueError("native build record belongs to another Git revision")
    if require_clean and (not record["git_tree_clean"] or not clean):
        raise ValueError("native build record or qualifying tree is dirty")
    tools = record["toolchain"]
    if not isinstance(tools, dict) or set(tools) != TOOLCHAIN_FIELDS:
        raise ValueError("invalid native toolchain record")
    rustc = bounded_tool_text(tools["rustc_verbose"], "recorded Rust compiler")
    bounded_tool_text(tools["cargo_version"], "recorded Cargo version")
    if re.findall(r"(?m)^host: (\S+)$", rustc) != [target]:
        raise ValueError("recorded Rust host differs from native target")
    if tools != {"rustc_verbose": command_output(["rustc", "-vV"]),
                 "cargo_version": command_output(["cargo", "-V"])}:
        raise ValueError("qualifying toolchain differs from build observation")
    host = record["host"]
    if not isinstance(host, dict) or set(host) != HOST_FIELDS:
        raise ValueError("invalid native build host record")
    for key in HOST_FIELDS:
        bounded_text(host[key], f"host {key}")
    if host["system"] != TARGET_SYSTEMS[target] or host["machine"].casefold() not in {"x86_64", "amd64"}:
        raise ValueError("recorded host differs from native target")


def checked_record(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECORD_BYTES:
        raise ValueError("native build record must be a bounded regular file")
    return load_json(path.read_bytes())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--output", type=Path)
    choice.add_argument("--verify", type=Path)
    parser.add_argument("--require-clean", action="store_true")
    args = parser.parse_args()
    if args.output is not None:
        record = make_record(args.binary, args.require_clean)
        body = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()
        if len(body) > MAX_RECORD_BYTES:
            raise ValueError("native build record exceeds size limit")
        if args.output.exists() or args.output.is_symlink():
            if args.output.is_symlink() or args.output.read_bytes() != body:
                raise ValueError("existing native build record differs")
        else:
            args.output.write_bytes(body)
        print(f"Native build observation: {args.output}; SHA-256: {sha256(body)}")
    else:
        validate_record(checked_record(args.verify), args.binary, args.require_clean)
        print(f"Native build observation verified: {args.verify}")


if __name__ == "__main__":
    main()
