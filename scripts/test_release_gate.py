"""Synthetic negative gate tests; none of these fixtures is native evidence."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PureWindowsPath
import tempfile
import unittest

import release_gate as gate


class ReleaseGateTests(unittest.TestCase):
    def test_source_paths_use_platform_independent_relative_order(self):
        root = PureWindowsPath("C:/source")
        paths = [root / name for name in ("build.rs", "Cargo.toml", "src/main.rs")]
        self.assertEqual(
            [path.relative_to(root).as_posix() for path in sorted(paths)],
            ["build.rs", "Cargo.toml", "src/main.rs"],
        )
        self.assertEqual(
            [path.relative_to(root).as_posix() for path in sorted(
                paths, key=lambda item: item.relative_to(root).as_posix().encode("utf-8"))],
            ["Cargo.toml", "build.rs", "src/main.rs"],
        )

    def fixture(self, root):
        for filename in ["Cargo.toml", "Cargo.lock", "src/main.rs"]:
            path = root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic source")
        target = dict(codex_version="0.156.0", os="windows", arch="x86_64",
                      os_release="synthetic-windows", os_build="synthetic-build",
                      sandbox="windows-elevated", surface="native-cli",
                      protocol="permission-request-v1", tool="Bash", codex_binary_sha256="a" * 64,
                      codex_bundle_sha256="d" * 64, launch_kind="npm-cmd", launch_artifact_sha256="e" * 64,
                      launch_package_sha256="f" * 64)
        runtime = dict(schema_version=2, autoapprover_version="0.1.0",
                       entries=[dict(evidence_id="synthetic-test", target=target)], revoked_artifact_sha256=[])
        path = root / "compatibility/manifest.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(runtime))
        artifact = root / "compatibility/evidence/synthetic/log.txt"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("Synthetic fixture only; this is never committed as live evidence.\n")
        artifact_ref = dict(path=artifact.relative_to(root).as_posix(), sha256=gate.sha256(artifact.read_bytes()))
        sbom_path = root / "compatibility/evidence/synthetic/binary.spdx.json"
        binary_sha = "b" * 64
        source_sha = gate.source_digest(root)
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "files": [{"SPDXID": gate.SBOM_FILE_ID,
                       "fileName": "./codex-autoapprover-windows-x86_64.exe",
                       "checksums": [{"algorithm": "SHA256", "checksumValue": binary_sha}]}],
            "packages": [{"SPDXID": "SPDXRef-Package-codex-autoapprover-0.1.0"}],
            "documentDescribes": [gate.SBOM_FILE_ID, "SPDXRef-Package-codex-autoapprover-0.1.0"],
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                               "relatedSpdxElement": gate.SBOM_FILE_ID,
                               "relationshipType": "DESCRIBES"}],
            "annotations": [{"annotator": "Tool: scripts/binary_sbom.py",
                             "comment": ("Native Rust target: x86_64-pc-windows-msvc; consumer executable SHA-256: "
                                         f"{binary_sha}; source SHA-256: {source_sha}")}],
        }
        sbom_path.write_text(json.dumps(sbom))
        sbom_ref = dict(path=sbom_path.relative_to(root).as_posix(), sha256=gate.sha256(sbom_path.read_bytes()))
        evidence = dict(schema_version=2, kind="native-live", evidence_id="synthetic-test", target=target,
                        source_sha256=source_sha, autoapprover_binary_sha256=binary_sha,
                        upstream_artifact_sha256="c" * 64, producer="synthetic-producer", reviewer="synthetic-reviewer",
                        review_decision="approved", run_url="https://example.invalid/synthetic-fixture",
                        observed_at=datetime.now(timezone.utc).isoformat(), artifacts=[artifact_ref, sbom_ref],
                        checks={check: {"result": "pass", "artifacts": [
                            sbom_ref["path"] if check == "consumer_binary_sbom" else artifact_ref["path"]]}
                                for check in gate.CHECKS})
        path = root / "compatibility/evidence/synthetic/report.json"
        path.write_text(json.dumps(evidence))
        certificate = dict(evidence_id="synthetic-test", evidence=path.relative_to(root).as_posix(),
                           sha256=gate.sha256(path.read_bytes()))
        policy = dict(schema_version=2, autoapprover_version="0.1.0", ready=True,
                      certifications=[certificate], blockers=[])
        return policy, runtime

    def rewrite_evidence(self, root, policy, change):
        ref = policy["certifications"][0]
        path = root / ref["evidence"]
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))
        ref["sha256"] = gate.sha256(path.read_bytes())

    def test_current_pending_policy_cannot_build_production_artifacts(self):
        root = Path(__file__).resolve().parent.parent
        policy = gate.load_json((root / "compatibility/release-policy.json").read_bytes())
        gate.validate(root, policy)
        with self.assertRaisesRegex(ValueError, "blocked"):
            gate.validate(root, policy, require_ready=True)

    def test_native_report_binds_every_field_and_consumer_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, runtime = self.fixture(root)
            gate.validate(root, policy, runtime, True, "b" * 64)
            for field in gate.TARGET_FIELDS:
                changed = copy.deepcopy(runtime)
                changed["entries"][0]["target"][field] += "-different"
                with self.subTest(field=field), self.assertRaises(ValueError):
                    gate.validate(root, policy, changed, True, "b" * 64)
            with self.assertRaisesRegex(ValueError, "consumer executable"):
                gate.validate(root, policy, runtime, True, "d" * 64)
            (root / "src/main.rs").write_text("new implementation")
            with self.assertRaisesRegex(ValueError, "different source"):
                gate.validate(root, policy, runtime, True, "b" * 64)

    def test_matching_edited_manifest_still_invalidates_old_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, runtime = self.fixture(root)
            runtime["entries"][0]["target"]["os_build"] = "another-build"
            (root / "compatibility/manifest.json").write_text(json.dumps(runtime))
            self.rewrite_evidence(root, policy, lambda evidence: evidence["target"].update(os_build="another-build"))
            with self.assertRaisesRegex(ValueError, "different source"):
                gate.validate(root, policy, runtime, True, "b" * 64)

    def test_forged_or_unsubstantiated_evidence_fails(self):
        changes = {
            "checks": lambda e: e["checks"].pop("one_request_allow"),
            "self-review": lambda e: e.update(reviewer=e["producer"].upper()),
            "retained-log": lambda e: e.update(artifacts=[]),
            "unchecked-log": lambda e: e["checks"]["one_request_allow"].update(artifacts=["not-retained"]),
            "stale": lambda e: e.update(observed_at=(datetime.now(timezone.utc) - timedelta(days=31)).isoformat()),
            "future": lambda e: e.update(observed_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat()),
            "wrong-source": lambda e: e.update(source_sha256="f" * 64),
            "wrong-tool": lambda e: e["target"].update(tool="apply_patch"),
            "wrong-version": lambda e: e["target"].update(codex_version="0.157.0"),
            "cross-compiled": lambda e: e.update(kind="cross-compiled"),
            "boolean-schema": lambda e: e.update(schema_version=True),
        }
        for label, change in changes.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, runtime = self.fixture(root)
                self.rewrite_evidence(root, policy, change)
                with self.assertRaises(ValueError):
                    gate.validate(root, policy, runtime, True, "b" * 64)

    def test_revocation_duplicates_and_missing_evidence_fail(self):
        for change in ["revoked-binary", "revoked-bundle", "revoked-launcher", "revoked-package",
                       "duplicate", "missing", "symlink", "artifact-changed"]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, runtime = self.fixture(root)
                if change.startswith("revoked-"):
                    digest = {"revoked-binary": "a", "revoked-bundle": "d",
                              "revoked-launcher": "e", "revoked-package": "f"}[change]
                    runtime["revoked_artifact_sha256"].append(digest * 64)
                if change == "duplicate": runtime["entries"].append(copy.deepcopy(runtime["entries"][0]))
                if change == "missing": policy["certifications"] = []
                if change == "symlink":
                    path = root / "compatibility/evidence/synthetic/log.txt"
                    path.unlink()
                    path.symlink_to(root / "Cargo.toml")
                if change == "artifact-changed": (root / "compatibility/evidence/synthetic/log.txt").write_text("changed")
                with self.assertRaises(ValueError):
                    gate.validate(root, policy, runtime, True, "b" * 64)

    def test_binary_sbom_must_bind_the_reviewed_consumer_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, runtime = self.fixture(root)
            path = root / "compatibility/evidence/synthetic/binary.spdx.json"
            document = json.loads(path.read_text())
            document["files"][0]["checksums"][0]["checksumValue"] = "f" * 64
            path.write_text(json.dumps(document))
            self.rewrite_evidence(root, policy, lambda evidence: next(
                artifact for artifact in evidence["artifacts"] if artifact["path"].endswith(".spdx.json")
            ).update(sha256=gate.sha256(path.read_bytes())))
            with self.assertRaisesRegex(ValueError, "binary SBOM"):
                gate.validate(root, policy, runtime, True, "b" * 64)

    def test_duplicate_json_fields_are_rejected_recursively(self):
        for text in ['{"ready":false,"ready":true}', '{"target":{"os":"linux","os":"windows"}}',
                     '{"score":NaN}', '{"score":Infinity}']:
            with self.assertRaises(ValueError):
                gate.load_json(text)


if __name__ == "__main__":
    unittest.main()
