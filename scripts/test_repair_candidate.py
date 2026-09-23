"""Bounded repair fixtures do not establish live Codex compatibility."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import repair_candidate as repair
import apply_repair
from test_verify_candidate_asset import candidate as asset_candidate


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo)


class RepairBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        (self.repo / "src").mkdir()
        (self.repo / "tests").mkdir()
        (self.repo / "compatibility").mkdir()
        (self.repo / "compatibility/candidate.json").write_text(json.dumps(asset_candidate()))
        (self.repo / "src/main.rs").write_text("fn main() {}\n")
        git(self.repo, "add", ".")
        subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                        "commit", "-qm", "baseline"], cwd=self.repo, check=True)
        self.base = repair.clean_base(self.repo)

    def test_small_rust_change_yields_reviewable_patch(self):
        (self.repo / "src/main.rs").write_text("fn main() { println!(\"test\"); }\n")
        paths, patch = repair.collect_patch(self.repo, self.base)
        self.assertEqual(paths, ["src/main.rs"])
        self.assertIn(b"+fn main()", patch)

    def test_manifest_workflow_and_symlink_changes_are_rejected(self):
        for path, content in [
            ("compatibility/manifest.json", "{}"),
            (".github/workflows/ci.yml", "name: unsafe"),
        ]:
            with self.subTest(path=path):
                destination = self.repo / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content)
                with self.assertRaisesRegex(ValueError, "forbidden path"):
                    repair.collect_patch(self.repo, self.base)
                destination.unlink()
        (self.repo / "src/link.rs").symlink_to(self.repo / "src/main.rs")
        with self.assertRaisesRegex(ValueError, "invalid Rust file"):
            repair.collect_patch(self.repo, self.base)

    def test_untracked_rust_test_is_included_but_new_commit_is_rejected(self):
        (self.repo / "tests/repair.rs").write_text("#[test] fn repair() {}\n")
        paths, patch = repair.collect_patch(self.repo, self.base)
        self.assertEqual(paths, ["tests/repair.rs"])
        self.assertIn(b"tests/repair.rs", patch)
        git(self.repo, "add", ".")
        subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                        "commit", "-qm", "agent-commit"], cwd=self.repo, check=True)
        with self.assertRaisesRegex(ValueError, "branch history"):
            repair.collect_patch(self.repo, self.base)

    def test_trusted_apply_checks_base_digest_and_exact_paths(self):
        (self.repo / "src/main.rs").write_text("fn main() { println!(\"repair\"); }\n")
        paths, patch = repair.collect_patch(self.repo, self.base)
        patch_path = self.root / "repair.patch"
        patch_path.write_bytes(patch)
        destination = self.root / "apply"
        subprocess.run(["git", "clone", "-q", str(self.repo), str(destination)], check=True)
        report = {"schema_version": 1, "codex_version": "0.156.0", "base_sha": self.base,
                  "upstream_source_sha": "b" * 40,
                  "changed_paths": paths, "patch_sha256": hashlib.sha256(patch).hexdigest(),
                  "checks": ["format", "rust-tests", "clippy"],
                  "status": "proposed-unverified", "certified": False}
        self.assertEqual(apply_repair.apply(destination, patch_path, report, "0.156.0"), paths)
        self.assertIn("repair", (destination / "src/main.rs").read_text())
        with self.assertRaisesRegex(ValueError, "repair worktree must start clean"):
            apply_repair.apply(destination, patch_path, report, "0.156.0")
        another = self.root / "another"
        subprocess.run(["git", "clone", "-q", str(self.repo), str(another)], check=True)
        with self.assertRaisesRegex(ValueError, "integrity failed"):
            apply_repair.apply(another, patch_path, {**report, "patch_sha256": "f" * 64}, "0.156.0")
        with self.assertRaisesRegex(ValueError, "source differs from the pinned candidate"):
            apply_repair.apply(another, patch_path, {**report, "upstream_source_sha": "f" * 40}, "0.156.0")

    def test_trusted_apply_rejects_forbidden_patch_path(self):
        destination = self.repo / "compatibility/manifest.json"
        destination.parent.mkdir(exist_ok=True)
        destination.write_text("{}\n")
        git(self.repo, "add", "-N", "--", "compatibility/manifest.json")
        patch_path = self.root / "forbidden.patch"
        patch_path.write_bytes(git(self.repo, "diff", "--binary", "HEAD"))
        with self.assertRaisesRegex(ValueError, "forbidden path"):
            apply_repair.patch_paths(self.repo, patch_path)

    def test_binary_repair_artifacts_fail_before_git_applies_them(self):
        (self.repo / "src/main.rs").write_bytes(b"fn main() {}\0" + b"A" * 10000)
        binary_patch = git(self.repo, "diff", "--binary", "HEAD")
        self.assertIn(b"GIT binary patch", binary_patch)
        patch_path = self.root / "repair.patch"
        patch_path.write_bytes(binary_patch)
        with self.assertRaisesRegex(ValueError, "only text changes"):
            apply_repair.patch_paths(self.repo, patch_path)

        for label, body, message in (
            ("git-binary", binary_patch, "only text changes"),
            ("nul", b"not a patch\0", "only text changes"),
            ("invalid-utf8", b"not a patch\xff", "UTF-8 text"),
        ):
            with self.subTest(label=label):
                patch_path.write_bytes(body)
                destination = self.root / f"apply-{label}"
                subprocess.run(["git", "clone", "-q", str(self.repo), str(destination)], check=True)
                report = {"schema_version": 1, "codex_version": "0.156.0", "base_sha": self.base,
                          "upstream_source_sha": "b" * 40,
                          "changed_paths": ["src/main.rs"],
                          "patch_sha256": hashlib.sha256(body).hexdigest(),
                          "checks": ["format", "rust-tests", "clippy"],
                          "status": "proposed-unverified", "certified": False}
                with patch.object(apply_repair, "patch_paths") as parse:
                    with self.assertRaisesRegex(ValueError, message):
                        apply_repair.apply(destination, patch_path, report, "0.156.0")
                    parse.assert_not_called()

    def test_write_token_job_rejects_ambiguous_or_unbounded_repair_artifacts(self):
        report_path = self.root / "repair-report.json"
        report_path.write_text('{"status":"proposed-unverified","status":"certified"}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            apply_repair.load_report(report_path)

        with report_path.open("wb") as stream:
            stream.seek(apply_repair.MAX_REPORT_BYTES)
            stream.write(b"x")
        with self.assertRaisesRegex(ValueError, "repair report exceeds"):
            apply_repair.load_report(report_path)

        patch_path = self.root / "repair.patch"
        with patch_path.open("wb") as stream:
            stream.seek(repair.MAX_PATCH_BYTES)
            stream.write(b"x")
        with self.assertRaisesRegex(ValueError, "repair patch exceeds"):
            apply_repair.read_artifact(patch_path, repair.MAX_PATCH_BYTES, "repair patch")

        report_path.write_text("{}")
        alias = self.root / "linked-report.json"
        alias.symlink_to(report_path)
        with self.assertRaisesRegex(ValueError, "regular singly linked"):
            apply_repair.load_report(alias)

    def test_trusted_apply_uses_the_verified_patch_bytes_after_artifact_replacement(self):
        source = self.repo / "src/main.rs"
        source.write_text('fn main() { println!("reviewed"); }\n')
        paths, reviewed_patch = repair.collect_patch(self.repo, self.base)
        source.write_text('fn main() { println!("swapped"); }\n')
        _, swapped_patch = repair.collect_patch(self.repo, self.base)
        patch_path = self.root / "repair.patch"
        patch_path.write_bytes(reviewed_patch)
        destination = self.root / "apply"
        subprocess.run(["git", "clone", "-q", str(self.repo), str(destination)], check=True)
        report = {"schema_version": 1, "codex_version": "0.156.0", "base_sha": self.base,
                  "upstream_source_sha": "b" * 40,
                  "changed_paths": paths, "patch_sha256": hashlib.sha256(reviewed_patch).hexdigest(),
                  "checks": ["format", "rust-tests", "clippy"],
                  "status": "proposed-unverified", "certified": False}
        original_patch_paths = apply_repair.patch_paths

        def replace_downloaded_patch(repo, verified_path):
            patch_path.write_bytes(swapped_patch)
            return original_patch_paths(repo, verified_path)

        with patch.object(apply_repair, "patch_paths", side_effect=replace_downloaded_patch):
            self.assertEqual(apply_repair.apply(destination, patch_path, report, "0.156.0"), paths)
        self.assertIn("reviewed", (destination / "src/main.rs").read_text())
        self.assertNotIn("swapped", (destination / "src/main.rs").read_text())

    def test_repair_paths_exclude_traversal_and_controls(self):
        self.assertTrue(repair.allowed_repair_path("src/broker/linux.rs"))
        for path in ["src/../compatibility/manifest.rs", "src//main.rs",
                     "src/evil\nname.rs", "src/evil\\name.rs", ".github/workflows/ci.rs"]:
            with self.subTest(path=path):
                self.assertFalse(repair.allowed_repair_path(path))

    def test_cancelled_repair_process_group_is_reaped(self):
        process = subprocess.Popen(["sleep", "30"], start_new_session=True)
        repair.stop_process_group(process)
        self.assertIsNotNone(process.poll())

    def test_fake_agent_runs_once_without_repository_token_or_key_in_exec_environment(self):
        worker = self.root / "fake-codex"
        worker.write_text("""#!/usr/bin/env python3
import os, pathlib, sys
if sys.argv[1] == 'login':
    assert sys.stdin.read() == 'fixture-key\\n'
else:
    assert sys.argv[1] == 'exec'
    assert '--ephemeral' in sys.argv and '--ignore-user-config' in sys.argv
    assert 'workspace-write' in sys.argv
    assert 'CODEX_REPAIR_API_KEY' not in os.environ
    assert 'GH_TOKEN' not in os.environ
    assert 'Codex 0.156.0' in sys.stdin.read()
    pathlib.Path('src/main.rs').write_text('fn main() { println!("fixture"); }\\n')
""")
        worker.chmod(0o700)
        old_key = os.environ.get("CODEX_REPAIR_API_KEY")
        old_token = os.environ.get("GH_TOKEN")
        os.environ["CODEX_REPAIR_API_KEY"] = "should-not-leak"
        os.environ["GH_TOKEN"] = "should-not-leak"
        try:
            repair.run_agent(self.repo, "0.156.0", "fixture-key", codex=str(worker))
        finally:
            if old_key is None:
                os.environ.pop("CODEX_REPAIR_API_KEY", None)
            else:
                os.environ["CODEX_REPAIR_API_KEY"] = old_key
            if old_token is None:
                os.environ.pop("GH_TOKEN", None)
            else:
                os.environ["GH_TOKEN"] = old_token
        paths, _ = repair.collect_patch(self.repo, self.base)
        self.assertEqual(paths, ["src/main.rs"])


class RepairWorkflowFixtureTests(unittest.TestCase):
    def test_fake_repair_to_checked_patch_to_separate_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate_repo = root / "candidate"
            candidate_repo.mkdir()
            git(candidate_repo, "init", "-q")
            (candidate_repo / "src").mkdir()
            (candidate_repo / "compatibility").mkdir()
            (candidate_repo / "Cargo.toml").write_text(
                '[package]\nname = "synthetic-repair"\nversion = "0.1.0"\nedition = "2024"\n')
            (candidate_repo / "src/main.rs").write_text("fn main() {}\n")
            (candidate_repo / "compatibility/candidate.json").write_text(json.dumps(asset_candidate()))
            subprocess.run(["cargo", "generate-lockfile"], cwd=candidate_repo, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            git(candidate_repo, "add", ".")
            subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                            "commit", "-qm", "baseline"], cwd=candidate_repo, check=True)
            upstream = root / "upstream-source"
            upstream.mkdir()
            git(upstream, "init", "-q")
            (upstream / "README.md").write_text("synthetic upstream source\n")
            git(upstream, "add", ".")
            subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                            "commit", "-qm", "upstream"], cwd=upstream, check=True)
            git(upstream, "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                "tag", "-a", "rust-v0.156.0", "-m", "synthetic annotated release")
            pinned = asset_candidate()
            pinned["upstream_tag_ref_sha"] = git(
                upstream, "rev-parse", "refs/tags/rust-v0.156.0").decode().strip()
            pinned["upstream_source_sha"] = git(upstream, "rev-parse", "HEAD").decode().strip()
            (candidate_repo / "compatibility/candidate.json").write_text(json.dumps(pinned))
            git(candidate_repo, "add", "compatibility/candidate.json")
            subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                            "commit", "-qm", "pin synthetic upstream source"], cwd=candidate_repo, check=True)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            worker = fake_bin / "codex"
            worker.write_text("""#!/usr/bin/env python3
import pathlib, sys
if sys.argv[1] == 'login':
    assert sys.stdin.read() == 'fixture-key\\n'
else:
    assert 'Codex 0.156.0' in sys.stdin.read()
    pathlib.Path('src/main.rs').write_text('// synthetic repair\\nfn main() {}\\n')
""")
            worker.chmod(0o700)
            output = root / "repair-output"
            argv = ["repair_candidate.py", "--repo", str(candidate_repo), "--candidate",
                    str(candidate_repo / "compatibility/candidate.json"),
                    "--upstream-source", str(upstream), "--output", str(output),
                    "--codex", str(worker)]
            for field, message in [("upstream_tag_ref_sha", "tag object differs"),
                                   ("upstream_source_sha", "commit differs")]:
                changed = {**pinned, field: "f" * 40}
                (candidate_repo / "compatibility/candidate.json").write_text(json.dumps(changed))
                with patch.object(sys, "argv", argv), patch.dict(os.environ, {
                        "CODEX_REPAIR_API_KEY": "fixture-key"}), \
                     patch.object(repair, "run_agent") as agent:
                    with self.assertRaisesRegex(ValueError, message):
                        repair.main()
                    agent.assert_not_called()
            (candidate_repo / "compatibility/candidate.json").write_text(json.dumps(pinned))
            with patch.object(sys, "argv", argv), patch.dict(os.environ, {
                    "CODEX_REPAIR_API_KEY": "fixture-key"}):
                repair.main()
            report = json.loads((output / "repair-report.json").read_text())
            self.assertFalse(report["certified"])
            self.assertEqual(report["upstream_source_sha"], git(upstream, "rev-parse", "HEAD").decode().strip())
            application = root / "apply"
            subprocess.run(["git", "clone", "-q", str(candidate_repo), str(application)], check=True)
            paths = apply_repair.apply(application, output / "repair.patch", report, "0.156.0")
            self.assertEqual(paths, ["src/main.rs"])
            self.assertIn("synthetic repair", (application / "src/main.rs").read_text())


if __name__ == "__main__":
    unittest.main()
