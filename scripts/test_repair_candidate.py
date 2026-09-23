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
                  "upstream_source_sha": "a" * 40,
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

    def test_trusted_apply_rejects_forbidden_patch_path(self):
        destination = self.repo / "compatibility/manifest.json"
        destination.parent.mkdir()
        destination.write_text("{}\n")
        git(self.repo, "add", "-N", "--", "compatibility/manifest.json")
        patch_path = self.root / "forbidden.patch"
        patch_path.write_bytes(git(self.repo, "diff", "--binary", "HEAD"))
        with self.assertRaisesRegex(ValueError, "forbidden path"):
            apply_repair.patch_paths(self.repo, patch_path)

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
            git(upstream, "tag", "rust-v0.156.0")
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
                    "--upstream-source", str(upstream), "--output", str(output)]
            with patch.object(sys, "argv", argv), patch.dict(os.environ, {
                    "CODEX_REPAIR_API_KEY": "fixture-key",
                    "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"]}):
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
