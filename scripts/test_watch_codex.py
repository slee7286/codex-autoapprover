import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import watch_codex as watch


def release(version, **fields):
    tag = f"rust-v{version}"
    assets = [dict(id=index + 10, name=name, size=1000 + index,
                   digest=f"sha256:{index + 1:064x}",
                   browser_download_url=f"https://github.com/openai/codex/releases/download/{tag}/{name}")
              for index, name in enumerate(watch.REQUIRED_ASSETS)]
    return {"id": 1, "draft": False, "prerelease": False, "tag_name": tag,
            "assets": assets, **fields}


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
            legacy = {key: value for key, value in candidate.items() if key != "assets"}
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

    def test_missed_stable_release_stops_before_candidate_write(self):
        previous = watch.candidate_from_releases([release("0.156.0")])
        latest = release("0.156.2", id=3)
        intermediate = release("0.156.1", id=2)
        watch.verify_release_gap(previous, watch.candidate_from_releases([latest]),
                                 [latest, release("0.156.0")])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(json.dumps(previous))
            original = path.read_bytes()
            with patch("sys.argv", ["watch_codex.py", "--output", str(path)]), \
                 patch.object(watch, "fetch_latest_release", return_value=latest), \
                 patch.object(watch, "fetch_releases", return_value=[latest, intermediate, release("0.156.0")]):
                with self.assertRaisesRegex(ValueError, "multiple or inconsistent"):
                    watch.main()
            self.assertEqual(path.read_bytes(), original)

        changed_old = release("0.156.0", id=99)
        with self.assertRaisesRegex(ValueError, "previous release identity"):
            watch.verify_release_gap(previous, watch.candidate_from_releases([latest]),
                                     [latest, changed_old])

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
                        watch.prepare_pr(selected, Path("compatibility/candidate.json"))
                        self.assertTrue(any(call.args[0][:3] == ["gh", "pr", "create"]
                                            for call in runner.call_args_list))
                    else:
                        with self.assertRaisesRegex(ValueError, "manual recovery"):
                            watch.prepare_pr(selected, Path("compatibility/candidate.json"))
                        self.assertFalse(any(call.args[0][:3] == ["gh", "pr", "create"]
                                             for call in runner.call_args_list))


if __name__ == "__main__":
    unittest.main()
