#!/usr/bin/env python3
"""Require exact compiled compatibility and reviewed, retained native evidence.

Structural integrity is necessary, not proof that evidence is truthful. Protected
reviews and independently witnessed native runs remain required release gates.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

from watch_codex import version_key

TARGET_FIELDS = {
    "codex_version", "os", "arch", "os_release", "os_build", "sandbox",
    "surface", "protocol", "tool", "codex_binary_sha256", "codex_bundle_sha256",
    "launch_kind", "launch_artifact_sha256", "launch_package_sha256",
}
CHECKS = {
    "shell_execution", "file_edit", "one_request_allow", "manual_fallback",
    "unknown_version_rejected", "wrong_os_rejected", "schema_rejection",
    "session_isolation", "timeout_cleanup", "install_reinstall_uninstall",
    "config_preservation", "upgrade_rollback", "native_negative_cases",
    "security_review", "artifact_integrity", "environment_identity_binding",
    "no_interactive_prompt", "independent_command_outcome", "hook_composition",
    "replay_rejection", "descendant_forgery_rejection", "executable_replacement",
    "cancellation_cleanup", "concurrent_sessions", "clean_disposable_environment",
    "locked_dependency_inventory", "license_notice_review", "vulnerability_review",
    "consumer_binary_sbom", "signed_provenance", "protected_release_checks",
    "exact_consumer_artifact_rollback",
}
MAX_EVIDENCE_AGE = timedelta(days=30)
MAX_SBOM_BYTES = 16 * 1024 * 1024
SBOM_FILE_ID = "SPDXRef-File-ConsumerBinary"
SBOM_TARGETS = {
    ("linux", "x86_64"): ("x86_64-unknown-linux-gnu", "codex-autoapprover-linux-x86_64"),
    ("windows", "x86_64"): ("x86_64-pc-windows-msvc", "codex-autoapprover-windows-x86_64.exe"),
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(body):
    def reject_nonfinite(value):
        raise ValueError(f"non-finite JSON value: {value}")

    return json.loads(body, object_pairs_hook=unique_object, parse_constant=reject_nonfinite)


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def digest_value(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"unexpected or missing {label} fields")


def validate_target(target):
    exact_keys(target, TARGET_FIELDS, "target")
    if any(not isinstance(value, str) or not value for value in target.values()):
        raise ValueError("target fields must be nonempty strings")
    version_key(target["codex_version"])
    if target["arch"] not in {"x86_64", "aarch64"}:
        raise ValueError("unsupported architecture")
    sandboxes = {"linux": {"linux-bwrap", "linux-landlock"},
                 "windows": {"windows-elevated", "windows-unelevated"}}
    if target["sandbox"] not in sandboxes.get(target["os"], set()):
        raise ValueError("sandbox does not belong to declared OS")
    if (target["surface"], target["protocol"], target["tool"]) != ("native-cli", "permission-request-v1", "Bash"):
        raise ValueError("unsupported surface, protocol or tool")
    if target["launch_kind"] not in {"native", "npm-bin", "npm-cmd", "npm-ps1"}:
        raise ValueError("unsupported launch artifact type")
    launch_kinds = {"linux": {"native", "npm-bin"},
                    "windows": {"native", "npm-cmd", "npm-ps1"}}
    if target["launch_kind"] not in launch_kinds.get(target["os"], set()):
        raise ValueError("launch artifact type does not belong to declared OS")
    if any(not digest_value(target[field]) for field in ("codex_binary_sha256", "codex_bundle_sha256", "launch_artifact_sha256", "launch_package_sha256")):
        raise ValueError("missing exact Codex executable, bundle or launcher digest")
    return tuple(target[field] for field in sorted(TARGET_FIELDS))


def validate_manifest(manifest):
    exact_keys(manifest, {"schema_version", "autoapprover_version", "entries", "revoked_artifact_sha256"}, "manifest")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 2:
        raise ValueError("unsupported manifest schema")
    version_key(manifest["autoapprover_version"])
    if not isinstance(manifest["entries"], list) or not isinstance(manifest["revoked_artifact_sha256"], list):
        raise ValueError("invalid manifest collections")
    revoked = manifest["revoked_artifact_sha256"]
    if any(not digest_value(value) for value in revoked) or len(set(revoked)) != len(revoked):
        raise ValueError("invalid artifact revocations")
    targets, ids = set(), set()
    for entry in manifest["entries"]:
        exact_keys(entry, {"evidence_id", "target"}, "certificate")
        identifier = entry["evidence_id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9-]+", identifier):
            raise ValueError("invalid evidence ID")
        target = validate_target(entry["target"])
        if target in targets or identifier in ids:
            raise ValueError("duplicate certificate")
        if any(entry["target"][field] in revoked for field in (
                "codex_binary_sha256", "codex_bundle_sha256", "launch_artifact_sha256", "launch_package_sha256")):
            raise ValueError("revoked Codex artifact is certified")
        targets.add(target)
        ids.add(identifier)


def regular_file(root, relative, directory=None):
    if not isinstance(relative, str):
        raise ValueError("file reference must be a string")
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {".", ".."} for part in relative.split("/")) or "\\" in relative:
        raise ValueError("file reference must be a canonical relative path")
    full = root / path
    for parent in [full, *full.parents]:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError("file references cannot traverse symlinks")
    if directory and not full.resolve().is_relative_to((root / directory).resolve()):
        raise ValueError("evidence must be retained under compatibility/evidence")
    if not full.is_file() or full.stat().st_nlink != 1:
        raise ValueError("referenced artifact must be a regular singly linked file")
    return full


def source_digest(root):
    """Evidence and policy excluded to avoid circular evidence hashes.

    The complete runtime manifest IS included: changing support, revocation,
    architecture or a binary digest invalidates every previous report.
    """
    root = root.resolve()
    paths = [root / name for name in ["Cargo.toml", "Cargo.lock", "compatibility/manifest.json"]]
    paths.extend(root / name for name in ["build.rs", "rust-toolchain", "rust-toolchain.toml", ".gitattributes"] if (root / name).exists())
    for directory in ["src", "tests", "scripts", ".github/workflows", ".cargo"]:
        paths.extend(path for path in (root / directory).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts)
    digest = hashlib.sha256()
    # Native Path ordering differs between Windows and Unix for mixed-case names.
    # Evidence produced on either runner must hash the same source byte sequence.
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix().encode("utf-8")):
        relative = path.relative_to(root).as_posix()
        regular_file(root, relative)
        digest.update(relative.encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def validate_binary_sbom(body, evidence, autoapprover_version):
    document = load_json(body)
    target = evidence["target"]
    identity = SBOM_TARGETS.get((target["os"], target["arch"]))
    if identity is None or not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("binary SBOM has an unsupported native target or SPDX version")
    triple, artifact_name = identity
    files = document.get("files")
    if not isinstance(files, list) or len(files) != 1:
        raise ValueError("binary SBOM lacks one exact consumer file")
    file = files[0]
    if (not isinstance(file, dict) or file.get("SPDXID") != SBOM_FILE_ID
            or file.get("fileName") != f"./{artifact_name}"
            or file.get("checksums") != [{"algorithm": "SHA256", "checksumValue": evidence["autoapprover_binary_sha256"]}]):
        raise ValueError("binary SBOM does not bind the consumer executable")
    root_id = f"SPDXRef-Package-codex-autoapprover-{autoapprover_version}"
    packages = document.get("packages")
    describes = document.get("documentDescribes")
    if (not isinstance(packages, list) or not any(
            isinstance(item, dict) and item.get("SPDXID") == root_id for item in packages)
            or not isinstance(describes, list)
            or SBOM_FILE_ID not in describes or root_id not in describes):
        raise ValueError("binary SBOM lacks described build inputs")
    relationships = document.get("relationships")
    if not isinstance(relationships, list) or not any(
            isinstance(item, dict) and item.get("spdxElementId") == "SPDXRef-DOCUMENT"
            and item.get("relatedSpdxElement") == SBOM_FILE_ID
            and item.get("relationshipType") == "DESCRIBES" for item in relationships):
        raise ValueError("binary SBOM does not describe the consumer file")
    expected_note = (f"Native Rust target: {triple}; consumer executable SHA-256: "
                     f"{evidence['autoapprover_binary_sha256']}; source SHA-256: {evidence['source_sha256']}")
    annotations = document.get("annotations")
    if not isinstance(annotations, list) or not any(
            isinstance(item, dict) and item.get("annotator") == "Tool: scripts/binary_sbom.py"
            and item.get("comment") == expected_note for item in annotations):
        raise ValueError("binary SBOM does not bind the native target and source")


def validate(root, policy, runtime=None, require_ready=False, binary_sha256=None, now=None):
    root = root.resolve()
    now = now or datetime.now(timezone.utc)
    exact_keys(policy, {"schema_version", "autoapprover_version", "ready", "certifications", "blockers"}, "release policy")
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 2 or type(policy["ready"]) is not bool:
        raise ValueError("invalid release policy schema")
    version_key(policy["autoapprover_version"])
    if not isinstance(policy["certifications"], list) or not isinstance(policy["blockers"], list):
        raise ValueError("invalid certification or blocker list")
    if any(not isinstance(blocker, str) or not blocker.strip() for blocker in policy["blockers"]):
        raise ValueError("invalid release blocker")
    manifest = load_json(regular_file(root, "compatibility/manifest.json").read_bytes())
    validate_manifest(manifest)
    if manifest["autoapprover_version"] != policy["autoapprover_version"]:
        raise ValueError("manifest and policy release versions differ")
    if runtime is not None:
        validate_manifest(runtime)
        if runtime != manifest:
            raise ValueError("compiled runtime manifest and repository manifest differ")
    source = source_digest(root)
    declared, binaries = set(), set()
    for certificate in policy["certifications"]:
        exact_keys(certificate, {"evidence_id", "evidence", "sha256"}, "evidence reference")
        identifier = certificate["evidence_id"]
        matches = [entry for entry in manifest["entries"] if entry["evidence_id"] == identifier]
        if len(matches) != 1 or identifier in declared:
            raise ValueError("duplicate evidence or certificate absent from runtime manifest")
        path = regular_file(root, certificate["evidence"], "compatibility/evidence")
        body = path.read_bytes()
        if sha256(body) != certificate["sha256"]:
            raise ValueError("evidence digest mismatch")
        evidence = load_json(body)
        if evidence.get("evidence_id") != identifier or evidence.get("target") != matches[0]["target"]:
            raise ValueError("evidence target does not equal the complete certified tuple")
        if evidence.get("source_sha256") != source:
            raise ValueError("evidence belongs to different source or manifest")
        if type(evidence.get("schema_version")) is not int or evidence["schema_version"] != 2 or evidence.get("kind") != "native-live":
            raise ValueError("evidence must be native live testing")
        for key in ["autoapprover_binary_sha256", "upstream_artifact_sha256"]:
            if not digest_value(evidence.get(key)):
                raise ValueError(f"missing exact {key}")
        binaries.add(evidence["autoapprover_binary_sha256"])
        producer, reviewer = evidence.get("producer"), evidence.get("reviewer")
        if not all(isinstance(value, str) and value.strip() == value and value for value in (producer, reviewer)) or producer.casefold() == reviewer.casefold():
            raise ValueError("independent producer and reviewer identities required")
        if evidence.get("review_decision") != "approved" or not re.fullmatch(r"https://[^/\s]+/\S+", evidence.get("run_url", "")):
            raise ValueError("missing approved review or durable evidence URL")
        try:
            observed = datetime.fromisoformat(evidence["observed_at"].replace("Z", "+00:00"))
            if observed.tzinfo is None or not timedelta(0) <= now - observed <= MAX_EVIDENCE_AGE:
                raise ValueError("native evidence is stale or future dated")
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError("missing native observation time") from error
        artifacts = evidence.get("artifacts", [])
        if not isinstance(artifacts, list) or not artifacts:
            raise ValueError("retained redacted artifacts required")
        retained = set()
        for artifact in artifacts:
            exact_keys(artifact, {"path", "sha256"}, "retained artifact")
            artifact_path = regular_file(root, artifact["path"], "compatibility/evidence")
            if sha256(artifact_path.read_bytes()) != artifact["sha256"] or artifact["path"] in retained:
                raise ValueError("artifact digest mismatch or duplicate")
            retained.add(artifact["path"])
        checks = evidence.get("checks", {})
        if not isinstance(checks, dict):
            raise ValueError("invalid native checks")
        for check in CHECKS:
            item = checks.get(check, {})
            refs = item.get("artifacts", []) if isinstance(item, dict) else []
            if not isinstance(item, dict) or item.get("result") != "pass" or not isinstance(refs, list) or not refs or any(ref not in retained for ref in refs):
                raise ValueError(f"native check has no passing retained evidence: {check}")
        sbom_refs = [reference for reference in checks["consumer_binary_sbom"]["artifacts"]
                     if reference.endswith(".spdx.json")]
        if len(sbom_refs) != 1:
            raise ValueError("consumer binary check requires one retained SPDX document")
        sbom_path = regular_file(root, sbom_refs[0], "compatibility/evidence")
        if sbom_path.stat().st_size > MAX_SBOM_BYTES:
            raise ValueError("consumer binary SBOM exceeds attestation size limit")
        validate_binary_sbom(sbom_path.read_bytes(), evidence, manifest["autoapprover_version"])
        declared.add(identifier)
    expected = {entry["evidence_id"] for entry in manifest["entries"]}
    if declared != expected:
        raise ValueError("every runtime certificate requires current reviewed evidence")
    if require_ready or policy["ready"]:
        if not policy["ready"] or policy["blockers"] or not declared:
            raise ValueError("production release blocked: qualification is incomplete")
        if runtime is None:
            raise ValueError("compiled runtime manifest is required")
        if not binary_sha256 or binary_sha256 not in binaries:
            raise ValueError("consumer executable has no current native qualification")


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
    policy = load_json((root / "compatibility/release-policy.json").read_bytes())
    runtime, binary_digest = None, None
    if args.binary:
        binary_digest = sha256(args.binary.read_bytes())
        runtime = load_json(subprocess.check_output([str(args.binary.resolve()), "support-matrix"], timeout=10))
        if binary_digest != sha256(args.binary.read_bytes()):
            raise ValueError("consumer executable changed during inspection")
    validate(root, policy, runtime, args.require_ready, binary_digest)
    print("Production qualification passed" if policy["ready"] else "Policy valid; production release remains BLOCKED")


if __name__ == "__main__":
    main()
