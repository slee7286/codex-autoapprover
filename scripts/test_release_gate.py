"""Synthetic negative gate tests; none of these fixtures is native evidence."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PureWindowsPath
import tempfile
import unittest
from unittest.mock import patch

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

    def fixture(self, root, platforms=("windows", "linux")):
        for filename in [
            "Cargo.toml", "Cargo.lock", "src/main.rs",
            "tools/repair-cli/package.json", "tools/repair-cli/package-lock.json",
        ]:
            path = root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic source")
        if any(platform not in {"linux", "windows"} for platform in platforms):
            raise ValueError("unknown synthetic platform")
        targets = {}
        for platform in platforms:
            targets[platform] = dict(
                codex_version="0.156.0", os=platform, arch="x86_64",
                os_release=f"synthetic-{platform}", os_build="synthetic-build",
                sandbox="windows-elevated" if platform == "windows" else "linux-bwrap",
                surface="native-cli", protocol="permission-request-v1", tool="Bash",
                codex_binary_sha256="a" * 64, codex_bundle_sha256="d" * 64,
                launch_kind="npm-cmd" if platform == "windows" else "npm-bin",
                launch_artifact_sha256="e" * 64, launch_package_sha256="f" * 64,
            )
        runtime = dict(schema_version=2, autoapprover_version="0.1.0",
                       entries=[dict(evidence_id="synthetic-test" if platform == "windows"
                                     else "synthetic-linux", target=targets[platform])
                                for platform in platforms], revoked_artifact_sha256=[])
        path = root / "compatibility/manifest.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(runtime))
        source_sha = gate.source_digest(root)
        build_commit = "1" * 40
        certificates = []
        for platform in platforms:
            target = targets[platform]
            binary_sha = ("b" if platform == "windows" else "6") * 64
            label = "synthetic" if platform == "windows" else "synthetic-linux"
            evidence_id = "synthetic-test" if platform == "windows" else "synthetic-linux"
            triple, artifact_name = gate.SBOM_TARGETS[(platform, "x86_64")]
            evidence_dir = root / "compatibility/evidence" / label
            evidence_dir.mkdir(parents=True)
            artifact = evidence_dir / "log.txt"
            artifact.write_text("Synthetic fixture only; this is never committed as live evidence.\n")
            artifact_ref = dict(path=artifact.relative_to(root).as_posix(),
                                sha256=gate.sha256(artifact.read_bytes()))
            sbom_path = evidence_dir / "binary.spdx.json"
            sbom = {
                "spdxVersion": "SPDX-2.3",
                "files": [{"SPDXID": gate.SBOM_FILE_ID, "fileName": f"./{artifact_name}",
                           "checksums": [{"algorithm": "SHA256", "checksumValue": binary_sha}]}],
                "packages": [{"SPDXID": "SPDXRef-Package-codex-autoapprover-0.1.0"}],
                "documentDescribes": [gate.SBOM_FILE_ID, "SPDXRef-Package-codex-autoapprover-0.1.0"],
                "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                                   "relatedSpdxElement": gate.SBOM_FILE_ID,
                                   "relationshipType": "DESCRIBES"}],
                "annotations": [{"annotator": "Tool: scripts/binary_sbom.py",
                                 "comment": (f"Native Rust target: {triple}; consumer executable SHA-256: "
                                             f"{binary_sha}; source SHA-256: {source_sha}")}],
            }
            sbom_path.write_text(json.dumps(sbom))
            sbom_ref = dict(path=sbom_path.relative_to(root).as_posix(),
                            sha256=gate.sha256(sbom_path.read_bytes()))
            build_path = evidence_dir / "build-record.json"
            build_record = {
                "schema_version": 1, "status": "unqualified-native-build-observation",
                "target": triple, "binary_sha256": binary_sha, "source_sha256": source_sha,
                "cargo_lock_sha256": gate.sha256((root / "Cargo.lock").read_bytes()),
                "manifest_sha256": gate.sha256((root / "compatibility/manifest.json").read_bytes()),
                "git_commit": build_commit, "git_tree_clean": True,
                "toolchain": {"rustc_verbose": f"rustc 1.98.0\nhost: {triple}\nrelease: 1.98.0",
                              "cargo_version": "cargo 1.98.0"},
                "host": {"system": "Windows" if platform == "windows" else "Linux",
                         "release": "synthetic", "version": "synthetic", "machine": "AMD64",
                         "distribution_id": "n/a", "distribution_version": "n/a"},
            }
            build_path.write_text(json.dumps(build_record))
            build_ref = dict(path=build_path.relative_to(root).as_posix(),
                             sha256=gate.sha256(build_path.read_bytes()))
            reproducibility_path = evidence_dir / "reproducibility.json"
            reproducibility = {
                "schema_version": 1, "status": "unqualified-native-reproducibility-observation",
                "git_commit": build_commit, "host": "win32" if platform == "windows" else "linux",
                "rustc": "rustc 1.98.0", "cargo": "cargo 1.98.0",
                "source_archive_sha256": "c" * 64, "source_sha256": source_sha,
                "expected_binary_sha256": binary_sha,
                "independent_build_sha256": [binary_sha, binary_sha], "byte_identical": True,
            }
            reproducibility_path.write_text(json.dumps(reproducibility))
            reproducibility_ref = dict(path=reproducibility_path.relative_to(root).as_posix(),
                                       sha256=gate.sha256(reproducibility_path.read_bytes()))
            evidence = dict(
                schema_version=2, kind="native-live", evidence_id=evidence_id, target=target,
                source_sha256=source_sha, autoapprover_binary_sha256=binary_sha,
                build_commit=build_commit, upstream_artifact_sha256="c" * 64,
                producer="synthetic-producer", reviewer="synthetic-reviewer",
                review_decision="approved", run_url="https://example.invalid/synthetic-fixture",
                observed_at=datetime.now(timezone.utc).isoformat(),
                artifacts=[artifact_ref, sbom_ref, build_ref, reproducibility_ref],
                checks={check: {"result": "pass", "artifacts": [
                    sbom_ref["path"] if check == "consumer_binary_sbom" else
                    build_ref["path"] if check == "consumer_build_record" else
                    reproducibility_ref["path"] if check == "consumer_reproducibility" else
                    artifact_ref["path"]]}
                        for check in gate.CHECKS},
            )
            report_path = evidence_dir / "report.json"
            report_path.write_text(json.dumps(evidence))
            certificates.append(dict(evidence_id=evidence_id,
                                     evidence=report_path.relative_to(root).as_posix(),
                                     sha256=gate.sha256(report_path.read_bytes())))
        policy = dict(schema_version=2, autoapprover_version="0.1.0", ready=True,
                      certifications=certificates, blockers=[])
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

    def test_ready_release_requires_both_native_platforms(self):
        for platform in ("linux", "windows"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, runtime = self.fixture(root, platforms=(platform,))
                with self.assertRaisesRegex(ValueError, "native Linux and Windows"):
                    gate.validate(root, policy, runtime, True,
                                  ("b" if platform == "windows" else "6") * 64, platform)

    def test_ready_binary_must_match_its_native_platform_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, runtime = self.fixture(root)
            gate.validate(root, policy, runtime, True, "b" * 64, "windows")
            gate.validate(root, policy, runtime, True, "6" * 64, "linux")
            with self.assertRaisesRegex(ValueError, "native qualification for this platform"):
                gate.validate(root, policy, runtime, True, "b" * 64)
            for binary, platform in (("b" * 64, "linux"), ("6" * 64, "windows")):
                with self.subTest(platform=platform), self.assertRaisesRegex(
                        ValueError, "native qualification for this platform"):
                    gate.validate(root, policy, runtime, True, binary, platform)

    def test_native_report_binds_every_field_and_consumer_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, runtime = self.fixture(root)
            gate.validate(root, policy, runtime, True, "b" * 64, "windows")
            for field in gate.TARGET_FIELDS:
                changed = copy.deepcopy(runtime)
                changed["entries"][0]["target"][field] += "-different"
                with self.subTest(field=field), self.assertRaises(ValueError):
                    gate.validate(root, policy, changed, True, "b" * 64, "windows")
            with self.assertRaisesRegex(ValueError, "consumer executable"):
                gate.validate(root, policy, runtime, True, "d" * 64, "windows")
            (root / "src/main.rs").write_text("new implementation")
            with self.assertRaisesRegex(ValueError, "different source"):
                gate.validate(root, policy, runtime, True, "b" * 64, "windows")

    def test_matching_edited_manifest_still_invalidates_old_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, runtime = self.fixture(root)
            runtime["entries"][0]["target"]["os_build"] = "another-build"
            (root / "compatibility/manifest.json").write_text(json.dumps(runtime))
            self.rewrite_evidence(root, policy, lambda evidence: evidence["target"].update(os_build="another-build"))
            with self.assertRaisesRegex(ValueError, "different source"):
                gate.validate(root, policy, runtime, True, "b" * 64, "windows")

    def test_repair_cli_inputs_are_bound_to_native_evidence(self):
        for filename in ("package.json", "package-lock.json"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, runtime = self.fixture(root)
                gate.validate(root, policy, runtime, True, "b" * 64, "windows")
                (root / "tools/repair-cli" / filename).write_text("different repair CLI input")
                with self.assertRaisesRegex(ValueError, "different source"):
                    gate.validate(root, policy, runtime, True, "b" * 64, "windows")

    def test_forged_or_unsubstantiated_evidence_fails(self):
        changes = {
            "checks": lambda e: e["checks"].pop("one_request_allow"),
            "missing-build-record": lambda e: e["checks"].pop("consumer_build_record"),
            "missing-reproducibility": lambda e: e["checks"].pop("consumer_reproducibility"),
            "self-review": lambda e: e.update(reviewer=e["producer"].upper()),
            "retained-log": lambda e: e.update(artifacts=[]),
            "unchecked-log": lambda e: e["checks"]["one_request_allow"].update(artifacts=["not-retained"]),
            "stale": lambda e: e.update(observed_at=(datetime.now(timezone.utc) - timedelta(days=31)).isoformat()),
            "future": lambda e: e.update(observed_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat()),
            "wrong-source": lambda e: e.update(source_sha256="f" * 64),
            "wrong-build-commit": lambda e: e.update(build_commit="f" * 40),
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
                    gate.validate(root, policy, runtime, True, "b" * 64, "windows")

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
                    gate.validate(root, policy, runtime, True, "b" * 64, "windows")

    def test_retained_paths_and_evidence_size_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, runtime = self.fixture(root)
            for path in (
                "compatibility/evidence//synthetic/log.txt",
                "compatibility/evidence/synthetic/log.txt/",
                "compatibility/evidence/synthetic:log.txt",
            ):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "canonical"):
                    gate.regular_file(root, path, "compatibility/evidence")
            policy["certifications"][0]["evidence"] = "compatibility/evidence//synthetic/report.json"
            with self.assertRaisesRegex(ValueError, "canonical"):
                gate.validate(root, policy, runtime, True, "b" * 64, "windows")

        for filename, limit, label in (
            ("report.json", gate.MAX_NATIVE_REPORT_BYTES, "native report"),
            ("log.txt", gate.MAX_RETAINED_ARTIFACT_BYTES, "retained artifact"),
        ):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, runtime = self.fixture(root)
                path = root / "compatibility/evidence/synthetic" / filename
                with path.open("wb") as stream:
                    stream.seek(limit)
                    stream.write(b"x")
                with self.assertRaisesRegex(ValueError, f"{label} exceeds"):
                    gate.validate(root, policy, runtime, True, "b" * 64, "windows")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, runtime = self.fixture(root)
            self.rewrite_evidence(root, policy, lambda evidence: evidence["artifacts"].extend(
                [evidence["artifacts"][0]] * gate.MAX_RETAINED_ARTIFACTS))
            with self.assertRaisesRegex(ValueError, "too numerous"):
                gate.validate(root, policy, runtime, True, "b" * 64, "windows")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, runtime = self.fixture(root)
            first = root / "compatibility/evidence/synthetic/log.txt"
            second = root / "compatibility/evidence/synthetic/binary.spdx.json"
            with patch.object(gate, "MAX_TOTAL_RETAINED_BYTES",
                              first.stat().st_size + second.stat().st_size - 1):
                with self.assertRaisesRegex(ValueError, "total size limit"):
                    gate.validate(root, policy, runtime, True, "b" * 64, "windows")

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
                gate.validate(root, policy, runtime, True, "b" * 64, "windows")

    def test_build_record_must_bind_reviewed_source_binary_and_clean_native_host(self):
        changes = {
            "binary": lambda record: record.update(binary_sha256="f" * 64),
            "source": lambda record: record.update(source_sha256="f" * 64),
            "lockfile": lambda record: record.update(cargo_lock_sha256="f" * 64),
            "manifest": lambda record: record.update(manifest_sha256="f" * 64),
            "dirty": lambda record: record.update(git_tree_clean=False),
            "target": lambda record: record.update(target="x86_64-unknown-linux-gnu"),
            "toolchain": lambda record: record["toolchain"].update(rustc_verbose="rustc 1.98.0\nhost: x86_64-unknown-linux-gnu"),
            "host": lambda record: record["host"].update(system="Linux"),
        }
        for label, change in changes.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, runtime = self.fixture(root)
                path = root / "compatibility/evidence/synthetic/build-record.json"
                record = json.loads(path.read_text())
                change(record)
                path.write_text(json.dumps(record))
                self.rewrite_evidence(root, policy, lambda evidence: next(
                    artifact for artifact in evidence["artifacts"] if artifact["path"].endswith("/build-record.json")
                ).update(sha256=gate.sha256(path.read_bytes())))
                with self.assertRaisesRegex(ValueError, "build record"):
                    gate.validate(root, policy, runtime, True, "b" * 64, "windows")

    def test_reproducibility_record_must_bind_the_reviewed_build(self):
        changes = {
            "binary": lambda report: report.update(expected_binary_sha256="f" * 64),
            "source": lambda report: report.update(source_sha256="f" * 64),
            "commit": lambda report: report.update(git_commit="f" * 40),
            "host": lambda report: report.update(host="linux"),
            "toolchain": lambda report: report.update(rustc="rustc 9.9.9"),
            "archive": lambda report: report.update(source_archive_sha256="invalid"),
            "rebuild": lambda report: report.update(independent_build_sha256=["b" * 64, "f" * 64]),
            "mismatch": lambda report: report.update(byte_identical=False),
        }
        for label, change in changes.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, runtime = self.fixture(root)
                path = root / "compatibility/evidence/synthetic/reproducibility.json"
                report = json.loads(path.read_text())
                change(report)
                path.write_text(json.dumps(report))
                self.rewrite_evidence(root, policy, lambda evidence: next(
                    artifact for artifact in evidence["artifacts"]
                    if artifact["path"].endswith("/reproducibility.json")
                ).update(sha256=gate.sha256(path.read_bytes())))
                with self.assertRaisesRegex(ValueError, "reproducibility record"):
                    gate.validate(root, policy, runtime, True, "b" * 64, "windows")

    def test_duplicate_json_fields_are_rejected_recursively(self):
        for text in ['{"ready":false,"ready":true}', '{"target":{"os":"linux","os":"windows"}}',
                     '{"score":NaN}', '{"score":Infinity}']:
            with self.assertRaises(ValueError):
                gate.load_json(text)


if __name__ == "__main__":
    unittest.main()
