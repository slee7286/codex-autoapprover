#!/usr/bin/env python3
"""Block production artifacts without fresh, reviewed native evidence.

Checks provenance/integrity, not the truth of evidence: independent review and
protected branches are required. Candidate automation cannot edit this policy.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from watch_codex import version_key

CHECKS = {
    "shell_execution", "file_edit", "one_request_allow", "manual_fallback",
    "unknown_version_rejected", "wrong_os_rejected", "schema_rejection",
    "session_isolation", "timeout_cleanup", "install_reinstall_uninstall",
    "config_preservation", "upgrade_rollback", "native_negative_cases",
    "security_review", "artifact_integrity", "environment_identity_binding",
}


def source_digest(root):
    """Bind evidence to code, dependencies, tests, installers and workflows.

    Evidence/docs are excluded to allow recording results without circular hashes.
    """
    paths = [root / "Cargo.toml", root / "Cargo.lock"]
    paths.extend(root / name for name in ["build.rs", "rust-toolchain", "rust-toolchain.toml", ".gitattributes"] if (root / name).exists())
    for directory in ["src", "tests", "scripts", ".github/workflows", ".cargo"]:
        paths.extend(path for path in (root / directory).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts)
    digest = hashlib.sha256()
    for path in sorted(paths):
        if path.is_symlink():
            raise ValueError("source digest cannot contain symlinks")
        digest.update(path.relative_to(root).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def validate(root, policy, runtime=None, require_ready=False):
    if set(policy) != {"schema_version", "autoapprover_version", "ready", "certifications", "blockers"}:
        raise ValueError("unexpected release policy fields")
    if policy["schema_version"] != 1 or type(policy["ready"]) is not bool:
        raise ValueError("invalid release policy schema")
    version_key(policy["autoapprover_version"])
    if not isinstance(policy["certifications"], list) or not isinstance(policy["blockers"], list):
        raise ValueError("invalid certification or blocker list")
    declared = set()
    tuples = set()
    for certificate in policy["certifications"]:
        if set(certificate) != {"codex_version", "os", "arch", "os_release", "sandbox", "evidence", "sha256"}:
            raise ValueError("unexpected certificate fields")
        version_key(certificate["codex_version"])
        if certificate["os"] not in {"linux", "windows"} or certificate["arch"] not in {"x86_64", "aarch64"}:
            raise ValueError("unsupported certificate platform")
        if not certificate["os_release"] or certificate["sandbox"] not in {"linux", "elevated", "unelevated"}:
            raise ValueError("certificate must identify OS release and sandbox")
        if (certificate["os"] == "linux") != (certificate["sandbox"] == "linux"):
            raise ValueError("sandbox does not belong to the declared OS")
        key = tuple(certificate[field] for field in ("codex_version", "os", "arch", "os_release", "sandbox"))
        if key in tuples:
            raise ValueError("duplicate certification")
        tuples.add(key)
        evidence_root = (root / "compatibility/evidence").resolve()
        path = root / certificate["evidence"]
        if path.is_symlink() or not path.resolve().is_relative_to(evidence_root):
            raise ValueError("evidence must be a regular file under compatibility/evidence")
        body = path.read_bytes()
        if hashlib.sha256(body).hexdigest() != certificate["sha256"]:
            raise ValueError("evidence digest mismatch")
        evidence = json.loads(body)
        if evidence.get("source_sha256") != source_digest(root):
            raise ValueError("evidence belongs to different source code")
        for field in ("codex_version", "os", "arch", "os_release", "sandbox"):
            if evidence.get(field) != certificate[field]:
                raise ValueError("evidence tuple mismatch")
        if evidence.get("schema_version") != 1 or evidence.get("kind") != "native-live":
            raise ValueError("evidence must be native live testing")
        if not re.fullmatch(r"[0-9a-f]{64}", evidence.get("codex_binary_sha256", "")):
            raise ValueError("missing exact Codex binary digest")
        if not evidence.get("reviewer") or evidence.get("reviewer") == evidence.get("producer"):
            raise ValueError("independent review required")
        if evidence.get("review_decision") != "approved" or not evidence.get("run_url", "").startswith("https://"):
            raise ValueError("missing approved review or evidence run")
        checks = evidence.get("checks", {})
        if any(checks.get(check) != "pass" for check in CHECKS):
            raise ValueError("required evidence checks missing or failing")
        declared.add((certificate["codex_version"], certificate["os"]))
    if require_ready or policy["ready"]:
        if policy["ready"] is not True or policy["blockers"] or not declared:
            raise ValueError("production release blocked: qualification is incomplete")
        if runtime is None or runtime.get("schema_version") != 1:
            raise ValueError("runtime support matrix is required")
        if runtime.get("autoapprover_version") != policy["autoapprover_version"]:
            raise ValueError("runtime and policy release versions differ")
        actual = {(entry["codex_version"], entry["os"]) for entry in runtime["entries"]}
        if actual != declared:
            raise ValueError("runtime support and certified support differ")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-ready", action="store_true")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--print-source-digest", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    if args.print_source_digest:
        print(source_digest(root))
        return
    policy = json.loads((root / "compatibility/release-policy.json").read_text())
    runtime = None
    if args.binary:
        runtime = json.loads(subprocess.check_output([str(args.binary.resolve()), "support-matrix"], timeout=10))
    validate(root, policy, runtime, args.require_ready)
    print("Production qualification passed" if policy["ready"] else "Policy valid; production release remains BLOCKED")


if __name__ == "__main__":
    main()
