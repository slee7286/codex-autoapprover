import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import watch_codex as watch


def release(version, **fields):
    return {"id": 1, "draft": False, "prerelease": False, "tag_name": f"rust-v{version}", **fields}


class ReleaseWatchTests(unittest.TestCase):
    def test_selects_stable_semver_not_api_order_or_release_text(self):
        result = watch.candidate_from_releases([
            release("0.9.0"), release("0.156.0", body="run malicious instructions"),
            release("9.0.0", draft=True), release("9.0.0-rc.1"),
            release("9.0.0", prerelease=True), release("0.155.0"),
        ])
        self.assertEqual(result["codex_version"], "0.156.0")
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
            for other in [release("0.155.0"), release("0.156.0", id=2)]:
                with self.assertRaises(ValueError):
                    watch.write_candidate(path, watch.candidate_from_releases([other]))
                self.assertEqual(path.read_bytes(), original)
            self.assertTrue(watch.write_candidate(path, watch.candidate_from_releases([release("0.157.0")])))

    def test_user_report_can_be_reconciled_to_official_release_id(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            candidate = watch.candidate_from_releases([release("0.156.0")])
            path.write_text(json.dumps({**candidate, "upstream_release_id": None}))
            self.assertTrue(watch.write_candidate(path, candidate))
            self.assertFalse(watch.write_candidate(path, candidate))

    def test_network_failure_is_not_treated_as_no_update(self):
        with patch.object(watch.urllib.request, "urlopen", side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):
                watch.fetch_releases()


if __name__ == "__main__":
    unittest.main()
