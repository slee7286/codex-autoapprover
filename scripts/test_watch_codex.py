import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import watch_codex as watch
from npm_candidate import aliases, tarball_url


def release(version, **fields):
    tag = f"rust-v{version}"
    assets = [dict(id=index + 10, name=name, size=1000 + index,
                   digest=f"sha256:{index + 1:064x}",
                   browser_download_url=f"https://github.com/openai/codex/releases/download/{tag}/{name}")
              for index, name in enumerate(watch.REQUIRED_ASSETS)]
    return {"id": 1, "draft": False, "prerelease": False, "tag_name": tag,
            "assets": assets, **fields}


def npm_records(version):
    return [{"alias": alias, "version": package_version,
             "tarball": tarball_url(package_version),
             "integrity": "sha512-" + base64.b64encode(bytes([index]) * 64).decode("ascii")}
            for index, (alias, package_version, _, _) in enumerate(aliases(version))]


class ReleaseWatchTests(unittest.TestCase):
    def test_selects_stable_semver_not_api_order_or_release_text(self):
        result = watch.candidate_from_releases([
            release("0.9.0"), release("0.156.0", body="run malicious instructions"),
            release("9.0.0", draft=True), release("9.0.0-rc.1"),
            release("9.0.0", prerelease=True), release("0.155.0"),
        ])
        self.assertEqual(result["codex_version"], "0.156.0")
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual({asset["name"] for asset in result["assets"]}, set(watch.REQUIRED_ASSETS))
        self.assertEqual(result["status"], "unverified")
        self.assertNotIn("body", result)

    def test_invalid_and_untrusted_release_tags_do_not_become_commands(self):
        for version in ["1.2.3;echo bad", "1.2.3\n", "01.2.3", "../1.2.3", "1.2", "v1.2.3"]:
            with self.assertRaises(ValueError):
                watch.candidate_from_releases([release(version)])
        for response in [{"message": "rate limited"}, [None], [release("0.156.0", id="bad")]]:
            with self.assertRaises(ValueError):
                watch.candidate_from_releases(response)

    def test_idempotence_downgrade_and_replaced_release(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            candidate = watch.candidate_from_releases([release("0.156.0")])
            self.assertTrue(watch.write_candidate(path, candidate))
            self.assertFalse(watch.write_candidate(path, candidate))
            original = path.read_bytes()
            changed_assets = release("0.156.0")["assets"]
            changed_assets[0]["digest"] = "sha256:" + "f" * 64
            for other in [release("0.155.0"), release("0.156.0", id=2),
                          release("0.156.0", assets=changed_assets)]:
                with self.assertRaises(ValueError):
                    watch.write_candidate(path, watch.candidate_from_releases([other]))
                self.assertEqual(path.read_bytes(), original)
            self.assertTrue(watch.write_candidate(path, watch.candidate_from_releases([release("0.157.0")])))

    def test_user_report_can_be_reconciled_to_official_release_id(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            candidate = watch.candidate_from_releases([release("0.156.0")])
            candidate["npm_packages"] = npm_records("0.156.0")
            legacy = {key: value for key, value in candidate.items()
                      if key not in {"assets", "npm_packages"}}
            path.write_text(json.dumps({**legacy, "schema_version": 1, "upstream_release_id": None}))
            self.assertTrue(watch.write_candidate(path, candidate))
            self.assertFalse(watch.write_candidate(path, candidate))

    def test_required_native_asset_identity_is_strict(self):
        base = release("0.156.0")
        changes = [
            base["assets"][:1],
            base["assets"] + [base["assets"][0]],
            [{**base["assets"][0], "digest": "sha256:bad"}, base["assets"][1]],
            [{**base["assets"][0], "browser_download_url": "https://example.invalid/file"},
             base["assets"][1]],
        ]
        for assets in changes:
            with self.subTest(assets=assets), self.assertRaises(ValueError):
                watch.candidate_from_releases([release("0.155.0"), release("0.156.0", assets=assets)])

    def test_duplicate_prior_candidate_keys_are_rejected_before_update(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            original = b'{"codex_version":"0.156.0","codex_version":"0.156.1"}'
            path.write_bytes(original)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                watch.write_candidate(path, watch.candidate_from_releases([release("0.156.1")]))
            self.assertEqual(path.read_bytes(), original)

    def test_conflicting_duplicate_release_is_not_selected_by_api_order(self):
        with self.assertRaisesRegex(ValueError, "conflicting duplicate"):
            watch.candidate_from_releases([release("0.156.0"), release("0.156.0", id=2)])

    def test_page_limit_fails_instead_of_silently_truncating_release_history(self):
        class Response:
            def __init__(self, url):
                self.url = url

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def geturl(self):
                return self.url

            def read(self, _limit):
                return json.dumps([release("0.156.0"), release("0.155.0")]).encode()

        with patch.object(watch, "PAGE_SIZE", 2), patch.object(watch, "MAX_PAGES", 2):
            with self.assertRaisesRegex(ValueError, "pagination limit"):
                watch.fetch_releases(open_url=lambda request, timeout: Response(request.full_url))

    def test_default_page_size_reads_a_second_bounded_page(self):
        from urllib.parse import parse_qs, urlsplit

        pages = [
            [release(f"0.{minor}.0") for minor in range(156, 151, -1)],
            [release("0.151.0")],
        ]
        requested = []

        class Response:
            def __init__(self, url, page):
                self.url = url
                self.page = page

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def geturl(self):
                return self.url

            def read(self, _limit):
                return json.dumps(self.page).encode()

        def open_page(request, timeout):
            query = parse_qs(urlsplit(request.full_url).query)
            requested.append(query)
            self.assertEqual(query["per_page"], ["5"])
            return Response(request.full_url, pages[int(query["page"][0]) - 1])

        releases = watch.fetch_releases(open_url=open_page)
        self.assertEqual(len(releases), 6)
        self.assertEqual([page["page"] for page in requested], [["1"], ["2"]])
        requested.clear()
        recent = watch.fetch_releases(open_url=open_page, stop_tag="rust-v0.152.0")
        self.assertEqual(len(recent), 5)
        self.assertEqual([page["page"] for page in requested], [["1"]])
        with self.assertRaisesRegex(ValueError, "previous release absent"):
            watch.fetch_releases(open_url=lambda request, timeout:
                                 Response(request.full_url, [release("0.156.0")]),
                                 stop_tag="rust-v0.150.0")

    def test_latest_full_release_uses_one_bounded_official_request(self):
        selected = release("0.156.1")

        class Response:
            def __init__(self, url, body):
                self.url = url
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def geturl(self):
                return self.url

            def read(self, limit):
                return self.body[:limit]

        requested = []

        def open_latest(request, timeout):
            requested.append(request.full_url)
            self.assertEqual(request.full_url, watch.LATEST)
            self.assertEqual(timeout, 30)
            return Response(request.full_url, json.dumps(selected).encode())

        self.assertEqual(watch.fetch_latest_release(open_url=open_latest), selected)
        self.assertEqual(requested, [watch.LATEST])

        with patch.object(watch, "LIMIT", 8), self.assertRaisesRegex(ValueError, "exceeded limit"):
            watch.fetch_latest_release(open_url=open_latest)
        with self.assertRaisesRegex(ValueError, "redirect"):
            watch.fetch_latest_release(open_url=lambda request, timeout:
                                       Response("https://example.invalid/redirect", b"{}"))
        with self.assertRaisesRegex(ValueError, "unexpected response"):
            watch.fetch_latest_release(open_url=lambda request, timeout:
                                       Response(request.full_url, b"[]"))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            watch.fetch_latest_release(open_url=lambda request, timeout:
                                       Response(request.full_url, b'{"id":1,"id":2}'))

    def test_tagged_refresh_rejects_substitution_and_redirect(self):
        class Response:
            def __init__(self, url, release_record):
                self.url = url
                self.release_record = release_record

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def geturl(self):
                return self.url

            def read(self, limit):
                return json.dumps(self.release_record).encode()[:limit]

        def open_tag(request, timeout):
            self.assertEqual(request.full_url, watch.UPSTREAM + "/tags/rust-v0.156.1")
            return Response(request.full_url, release("0.156.1"))

        self.assertEqual(watch.fetch_tagged_release("0.156.1", open_url=open_tag)["id"], 1)
        with self.assertRaisesRegex(ValueError, "unexpected response"):
            watch.fetch_tagged_release("0.156.1", open_url=lambda request, timeout:
                                       Response(request.full_url, release("0.156.2")))
        with self.assertRaisesRegex(ValueError, "redirect"):
            watch.fetch_tagged_release("0.156.1", open_url=lambda request, timeout:
                                       Response("https://example.invalid/redirect", release("0.156.1")))
        with self.assertRaisesRegex(ValueError, "stable"):
            watch.fetch_tagged_release("0.156.1", open_url=lambda request, timeout:
                                       Response(request.full_url, release("0.156.1", prerelease=True)))

    def test_runner_refreshes_requested_older_candidate_without_latest_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate-runner.json"
            with patch("sys.argv", ["watch_codex.py", "--version", "0.156.1",
                                    "--output", str(path)]), \
                 patch.object(watch, "fetch_tagged_release", return_value=release("0.156.1")) as tagged, \
                 patch.object(watch, "fetch_latest_release") as latest, \
                 patch.object(watch, "fetch_npm_records", side_effect=npm_records):
                watch.main()
                tagged.assert_called_once_with("0.156.1")
                latest.assert_not_called()
            self.assertEqual(json.loads(path.read_text())["codex_version"], "0.156.1")

    def test_missed_stable_releases_are_selected_oldest_first(self):
        previous = watch.candidate_from_releases([release("0.156.0")])
        previous["npm_packages"] = npm_records("0.156.0")
        latest = release("0.156.2", id=3)
        intermediate = release("0.156.1", id=2)
        backlog = watch.verified_release_backlog(previous, watch.candidate_from_releases([latest]),
                                           [latest, intermediate, release("0.156.0")])
        self.assertEqual([item["codex_version"] for item in backlog], ["0.156.1", "0.156.2"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(json.dumps(previous))
            with patch("sys.argv", ["watch_codex.py", "--output", str(path)]), \
                 patch.object(watch, "fetch_latest_release", return_value=latest), \
                 patch.object(watch, "fetch_npm_records", side_effect=npm_records), \
                 patch.object(watch, "fetch_releases", return_value=[latest, intermediate, release("0.156.0")]):
                watch.main()
            self.assertEqual(json.loads(path.read_text())["codex_version"], "0.156.1")

        # GitHub's latest pointer need not be the greatest numeric version.
        backlog = watch.verified_release_backlog(previous, watch.candidate_from_releases([intermediate]),
                                           [intermediate, latest, release("0.156.0")])
        self.assertEqual([item["codex_version"] for item in backlog], ["0.156.1", "0.156.2"])

        changed_old = release("0.156.0", id=99)
        with self.assertRaisesRegex(ValueError, "previous release identity"):
            watch.verified_release_backlog(previous, watch.candidate_from_releases([latest]),
                                     [latest, changed_old])

    def test_previous_release_asset_drift_stops_the_next_candidate(self):
        previous = watch.candidate_from_releases([release("0.156.0")])
        latest = release("0.156.1", id=2)
        changed_old = release("0.156.0")
        changed_old["assets"][0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "previous release asset"):
            watch.verified_release_backlog(previous, watch.candidate_from_releases([latest]),
                                     [latest, changed_old])
        wrong_type = {**previous, "upstream_release_id": True}
        with self.assertRaises(ValueError):
            watch.verified_release_backlog(wrong_type, watch.candidate_from_releases([latest]),
                                     [latest, release("0.156.0")])

    def test_previous_npm_drift_stops_before_candidate_write(self):
        previous = watch.candidate_from_releases([release("0.156.0")])
        previous["npm_packages"] = npm_records("0.156.0")
        latest = release("0.156.1", id=2)

        def current_npm(version):
            records = npm_records(version)
            if version == "0.156.0":
                records[0]["integrity"] = "sha512-" + base64.b64encode(b"x" * 64).decode()
            return records

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(json.dumps(previous))
            original = path.read_bytes()
            with patch("sys.argv", ["watch_codex.py", "--output", str(path)]), \
                 patch.object(watch, "fetch_latest_release", return_value=latest), \
                 patch.object(watch, "fetch_releases", return_value=[latest, release("0.156.0")]), \
                 patch.object(watch, "fetch_npm_records", side_effect=current_npm) as fetched:
                with self.assertRaisesRegex(ValueError, "previous npm package identity changed"):
                    watch.main()
                fetched.assert_called_once_with("0.156.0")
            self.assertEqual(path.read_bytes(), original)

    def test_network_failure_is_not_treated_as_no_update(self):
        def fail(_request, timeout):
            raise TimeoutError

        with self.assertRaises(TimeoutError):
            watch.fetch_latest_release(open_url=fail)

    def test_candidate_branch_recovery_checks_metadata_and_changes_before_pr(self):
        selected = watch.candidate_from_releases([release("0.156.0")])
        for remote_candidate, paths, permitted in [
            (selected, "compatibility/candidate.json\n", True),
            ({**selected, "upstream_release_id": 999}, "compatibility/candidate.json\n", False),
            (selected, "compatibility/candidate.json\nsrc/main.rs\n", False),
        ]:
            with self.subTest(permitted=permitted, paths=paths):
                def output(command, text):
                    if command[:3] == ["gh", "pr", "list"]:
                        return "[]"
                    if command[:3] == ["git", "ls-remote", "--heads"]:
                        return "abc refs/heads/automation/codex-0.156.0\n"
                    if command[:2] == ["git", "show"]:
                        return json.dumps(remote_candidate)
                    if command[:3] == ["git", "diff", "--name-only"]:
                        return paths
                    self.fail(f"unexpected command: {command}")

                runner = Mock()
                with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}), \
                     patch.object(watch.subprocess, "check_output", side_effect=output), \
                     patch.object(watch.subprocess, "run", runner):
                    if permitted:
                        self.assertTrue(watch.prepare_pr(selected, Path("compatibility/candidate.json")))
                        self.assertTrue(any(call.args[0][:3] == ["gh", "pr", "create"]
                                            for call in runner.call_args_list))
                    else:
                        with self.assertRaisesRegex(ValueError, "manual recovery"):
                            watch.prepare_pr(selected, Path("compatibility/candidate.json"))
                        self.assertFalse(any(call.args[0][:3] == ["gh", "pr", "create"]
                                             for call in runner.call_args_list))

    def test_existing_pr_does_not_authorize_another_repair(self):
        selected = watch.candidate_from_releases([release("0.156.0")])
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}), \
             patch.object(watch.subprocess, "check_output", return_value=json.dumps([
                 {"number": 12, "headRefName": "automation/codex-0.156.0",
                  "headRepositoryOwner": {"login": "owner"}, "isCrossRepository": False}])), \
             patch.object(watch.subprocess, "run") as runner:
            self.assertFalse(watch.prepare_pr(selected, Path("compatibility/candidate.json")))
            runner.assert_not_called()

    def test_fork_pr_does_not_hide_our_candidate_and_ambiguous_head_fails(self):
        branch = "automation/codex-0.156.1"
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}), \
             patch.object(watch.subprocess, "check_output", return_value=json.dumps([
                 {"number": 12, "headRefName": branch,
                  "headRepositoryOwner": {"login": "someone-else"},
                  "isCrossRepository": True}])):
            self.assertFalse(watch.candidate_pr_exists("0.156.1"))
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}), \
             patch.object(watch.subprocess, "check_output", return_value=json.dumps([
                 {"number": 12, "headRefName": branch,
                  "headRepositoryOwner": {"login": "owner"},
                  "isCrossRepository": True}])):
            self.assertFalse(watch.candidate_pr_exists("0.156.1"))
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo"}), \
             patch.object(watch.subprocess, "check_output", return_value='[{"number":12}]'):
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                watch.candidate_pr_exists("0.156.1")

    def test_candidate_branch_sha_requires_one_exact_remote_ref(self):
        sha = "a" * 40
        ref = "refs/heads/automation/codex-0.156.0"
        for response, permitted in [
            (f"{sha}\t{ref}\n", True),
            (f"{sha}\t{ref}\n{sha}\t{ref}\n", False),
            (f"{sha}\trefs/heads/automation/codex-0.156.1\n", False),
            (f"short\t{ref}\n", False),
            ("", False),
        ]:
            with self.subTest(response=response), patch.object(
                    watch.subprocess, "check_output", return_value=response):
                if permitted:
                    self.assertEqual(watch.candidate_branch_sha("0.156.0"), sha)
                else:
                    with self.assertRaises(ValueError):
                        watch.candidate_branch_sha("0.156.0")

    def test_watcher_emits_pinned_branch_commit_after_draft_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate.json"
            baseline = watch.candidate_from_releases([release("0.155.0")])
            baseline["npm_packages"] = npm_records("0.155.0")
            candidate.write_text(json.dumps(baseline))
            output = root / "github-output.txt"
            argv = ["watch_codex.py", "--output", str(candidate), "--create-pr"]
            sha = "b" * 40
            with patch("sys.argv", argv), patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                 patch.object(watch, "fetch_latest_release", return_value=release("0.156.0")), \
                 patch.object(watch, "fetch_releases", return_value=[release("0.156.0"),
                                                                    release("0.155.0")]), \
                 patch.object(watch, "fetch_npm_records", side_effect=npm_records), \
                 patch.object(watch, "candidate_pr_exists", return_value=False), \
                 patch.object(watch, "prepare_pr", return_value=True) as prepare, \
                 patch.object(watch, "candidate_branch_sha", return_value=sha):
                watch.main()
                prepare.assert_called_once()
            self.assertIn(f"candidate_sha={sha}\n", output.read_text())
            self.assertIn("repair_eligible=true\n", output.read_text())

    def test_missing_baseline_cannot_create_only_latest_pr(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            with patch("sys.argv", ["watch_codex.py", "--output", str(path), "--create-pr"]), \
                 patch.object(watch, "fetch_latest_release") as fetched:
                with self.assertRaisesRegex(ValueError, "baseline candidate missing"):
                    watch.main()
                fetched.assert_not_called()

    def test_unchanged_release_without_candidate_branch_is_a_clean_noop(self):
        selected = watch.candidate_from_releases([release("0.156.0")])
        selected["npm_packages"] = npm_records("0.156.0")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate.json"
            candidate.write_text(json.dumps(selected))
            output = root / "github-output.txt"
            with patch("sys.argv", ["watch_codex.py", "--output", str(candidate), "--create-pr"]), \
                 patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                 patch.object(watch, "fetch_latest_release", return_value=release("0.156.0")), \
                 patch.object(watch, "fetch_releases", return_value=[release("0.156.0")]), \
                 patch.object(watch, "fetch_npm_records", return_value=npm_records("0.156.0")), \
                 patch.object(watch, "prepare_pr") as prepare, \
                 patch.object(watch, "candidate_branch_sha") as branch_sha:
                watch.main()
                prepare.assert_not_called()
                branch_sha.assert_not_called()
            self.assertIn("changed=false\n", output.read_text())
            self.assertIn("repair_eligible=false\n", output.read_text())
            self.assertNotIn("candidate_sha=", output.read_text())

    def test_existing_pr_is_skipped_without_spending_another_repair(self):
        previous = watch.candidate_from_releases([release("0.156.0")])
        previous["npm_packages"] = npm_records("0.156.0")
        latest = release("0.156.1", id=2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate.json"
            candidate.write_text(json.dumps(previous))
            output = root / "github-output.txt"
            with patch("sys.argv", ["watch_codex.py", "--output", str(candidate), "--create-pr"]), \
                 patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                 patch.object(watch, "fetch_latest_release", return_value=latest), \
                 patch.object(watch, "fetch_npm_records", side_effect=npm_records), \
                 patch.object(watch, "fetch_releases", return_value=[latest, release("0.156.0")]), \
                 patch.object(watch, "candidate_pr_exists", return_value=True) as exists, \
                 patch.object(watch, "prepare_pr", return_value=False) as prepare, \
                 patch.object(watch, "candidate_branch_sha", return_value="c" * 40):
                watch.main()
                exists.assert_called_once_with("0.156.1")
                prepare.assert_not_called()
            self.assertIn("changed=false\n", output.read_text())
            self.assertIn("repair_eligible=false\n", output.read_text())
            self.assertNotIn("candidate_sha=", output.read_text())
            self.assertEqual(json.loads(candidate.read_text()), previous)

    def test_each_poll_prepares_next_unhandled_release_from_same_baseline(self):
        baseline = watch.candidate_from_releases([release("0.156.0")])
        baseline["npm_packages"] = npm_records("0.156.0")
        releases = [release("0.156.3", id=4), release("0.156.2", id=3),
                    release("0.156.1", id=2), release("0.156.0")]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "candidate.json"
            output = root / "github-output.txt"
            prepared = []
            for existing in [(False,), (True, False), (True, True, False)]:
                path.write_text(json.dumps(baseline))
                output.write_text("")
                with patch("sys.argv", ["watch_codex.py", "--output", str(path), "--create-pr"]), \
                     patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                     patch.object(watch, "fetch_latest_release", return_value=releases[0]), \
                     patch.object(watch, "fetch_releases", return_value=releases), \
                     patch.object(watch, "fetch_npm_records", side_effect=npm_records), \
                     patch.object(watch, "candidate_pr_exists", side_effect=existing), \
                     patch.object(watch, "prepare_pr", return_value=True) as prepare, \
                     patch.object(watch, "candidate_branch_sha", return_value="f" * 40):
                    watch.main()
                    prepared.append(prepare.call_args.args[0]["codex_version"])
                self.assertIn("changed=true\n", output.read_text())
                self.assertIn("repair_eligible=true\n", output.read_text())
            self.assertEqual(prepared, ["0.156.1", "0.156.2", "0.156.3"])

    def test_manual_repair_retry_requires_existing_branch_even_without_update(self):
        selected = watch.candidate_from_releases([release("0.156.0")])
        selected["npm_packages"] = npm_records("0.156.0")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate.json"
            candidate.write_text(json.dumps(selected))
            output = root / "github-output.txt"
            argv = ["watch_codex.py", "--output", str(candidate), "--create-pr",
                    "--require-branch", "--version", "0.156.0"]
            with patch("sys.argv", argv), patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), \
                 patch.object(watch, "fetch_tagged_release", return_value=release("0.156.0")), \
                 patch.object(watch, "fetch_npm_records", return_value=npm_records("0.156.0")), \
                 patch.object(watch, "candidate_branch_sha", return_value="d" * 40) as branch_sha:
                watch.main()
                branch_sha.assert_called_once_with("0.156.0")
            self.assertIn(f"candidate_sha={'d' * 40}\n", output.read_text())
            self.assertIn("repair_eligible=false\n", output.read_text())

            with patch("sys.argv", argv), patch.dict(os.environ, {"GITHUB_OUTPUT": ""}), \
                 patch.object(watch, "fetch_tagged_release", return_value=release("0.156.0")), \
                 patch.object(watch, "fetch_npm_records", return_value=npm_records("0.156.0")), \
                 patch.object(watch, "candidate_branch_sha", side_effect=ValueError("branch missing")):
                with self.assertRaisesRegex(ValueError, "branch missing"):
                    watch.main()


if __name__ == "__main__":
    unittest.main()
