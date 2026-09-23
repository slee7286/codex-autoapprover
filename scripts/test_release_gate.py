import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import release_gate as gate


class ReleaseGateTests(unittest.TestCase):
    def fixture(self, root):
        for filename in ["Cargo.toml", "Cargo.lock", "src/main.rs"]:
            path = root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("test fixture")
        certificate = dict(codex_version="0.156.0", os="windows", arch="x86_64",
                           os_release="Windows test fixture", sandbox="elevated",
                           evidence="compatibility/evidence/test.json")
        # Synthetic test data only; never committed as production evidence.
        evidence = {**certificate, "schema_version": 1, "kind": "native-live",
                    "source_sha256": gate.source_digest(root), "codex_binary_sha256": "a" * 64,
                    "producer": "test-producer", "reviewer": "test-reviewer", "review_decision": "approved",
                    "run_url": "https://example.invalid/test-fixture", "checks": {check: "pass" for check in gate.CHECKS}}
        path = root / certificate["evidence"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(evidence))
        certificate["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        policy = dict(schema_version=1, autoapprover_version="0.1.0", ready=True,
                      certifications=[certificate], blockers=[])
        runtime = dict(schema_version=1, autoapprover_version="0.1.0",
                       entries=[dict(codex_version="0.156.0", os="windows")])
        return policy, runtime

    def test_pending_policy_cannot_build_production_artifacts(self):
        policy = dict(schema_version=1, autoapprover_version="0.1.0", ready=False, certifications=[], blockers=[])
        gate.validate(Path("."), policy)
        with self.assertRaises(ValueError):
            gate.validate(Path("."), policy, require_ready=True)

    def test_evidence_is_bound_to_code_and_cannot_promote_extra_runtime_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, runtime = self.fixture(root)
            gate.validate(root, policy, runtime, True)
            runtime["entries"].append(dict(codex_version="0.157.0", os="windows"))
            with self.assertRaises(ValueError):
                gate.validate(root, policy, runtime, True)
            runtime["entries"].pop()
            (root / "src/main.rs").write_text("new implementation")
            with self.assertRaises(ValueError):
                gate.validate(root, policy, runtime, True)

    def test_forged_digest_missing_checks_and_self_review_are_rejected(self):
        for change in ["digest", "checks", "reviewer", "path", "duplicate"]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, runtime = self.fixture(root)
                cert = policy["certifications"][0]
                path = root / cert["evidence"]
                evidence = json.loads(path.read_text())
                if change == "digest": cert["sha256"] = "0" * 64
                if change == "checks": evidence["checks"].pop("one_request_allow")
                if change == "reviewer": evidence["reviewer"] = evidence["producer"]
                if change == "path": cert["evidence"] = "Cargo.toml"
                if change == "duplicate": policy["certifications"].append(dict(cert))
                if change in {"checks", "reviewer"}:
                    path.write_text(json.dumps(evidence))
                    cert["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                with self.assertRaises(ValueError):
                    gate.validate(root, policy, runtime, True)


if __name__ == "__main__":
    unittest.main()
