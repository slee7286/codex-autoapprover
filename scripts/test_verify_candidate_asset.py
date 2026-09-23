"""Download integrity fixtures are not native approval evidence."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import verify_candidate_asset as check


PAYLOAD = b"synthetic native release asset"
VERSION = "0.156.0"


def candidate():
    assets = []
    for index, name in enumerate(check.REQUIRED_ASSETS):
        assets.append({
            "name": name, "id": index + 1, "size": len(PAYLOAD),
            "digest": "sha256:" + hashlib.sha256(PAYLOAD).hexdigest(),
            "url": f"https://github.com/openai/codex/releases/download/rust-v{VERSION}/{name}",
        })
    return {"schema_version": 2, "codex_version": VERSION,
            "upstream_tag": f"rust-v{VERSION}",
            "required_platforms": ["linux-x86_64", "windows-x86_64"],
            "status": "unverified", "assets": assets}


class Response(io.BytesIO):
    def __init__(self, payload, final_url="https://release-assets.githubusercontent.com/synthetic"):
        super().__init__(payload)
        self.final_url = final_url

    def geturl(self):
        return self.final_url


class VerifyCandidateAssetTests(unittest.TestCase):
    def test_exact_download_bytes_are_reported_only_as_integrity(self):
        for system in ["Linux", "Windows"]:
            with self.subTest(system=system):
                report = check.verify(candidate(), system, VERSION,
                                      open_url=lambda request, timeout: Response(PAYLOAD))
                self.assertEqual(report["sha256"], hashlib.sha256(PAYLOAD).hexdigest())
                self.assertFalse(report["certified"])

    def test_changed_bytes_size_and_redirect_are_rejected(self):
        for payload, final_url in [
            (b"changed synthetic native asset", "https://release-assets.githubusercontent.com/synthetic"),
            (PAYLOAD + b"extra", "https://release-assets.githubusercontent.com/synthetic"),
            (PAYLOAD, "https://example.invalid/synthetic"),
        ]:
            with self.subTest(payload=payload, final_url=final_url):
                with self.assertRaises(ValueError):
                    check.verify(candidate(), "Linux", VERSION,
                                 open_url=lambda request, timeout: Response(payload, final_url))

    def test_unknown_or_mismatched_candidate_never_downloads(self):
        for changed, system, version in [
            (candidate(), "Darwin", VERSION),
            (candidate(), "Linux", "0.157.0"),
            ({**candidate(), "status": "certified"}, "Linux", VERSION),
            ({**candidate(), "assets": candidate()["assets"][:1]}, "Linux", VERSION),
        ]:
            with self.subTest(system=system, version=version, changed=changed):
                with self.assertRaises(ValueError):
                    check.verify(changed, system, version,
                                 open_url=lambda request, timeout: self.fail("unexpected download"))

    def test_asset_redirect_rejects_non_github_hosts_before_following(self):
        with self.assertRaisesRegex(ValueError, "unexpected release asset redirect"):
            check.AllowedAssetRedirect().redirect_request(
                None, None, 302, "redirect", {}, "https://example.invalid/synthetic")

    def test_candidate_branch_metadata_must_match_refreshed_official_identity(self):
        official = candidate()
        check.require_recorded_candidate_matches_official(official, candidate())
        changed = candidate()
        changed["assets"][0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "differs from current official release"):
            check.require_recorded_candidate_matches_official(official, changed)
        changed = candidate()
        changed["assets"][0]["id"] = float(changed["assets"][0]["id"])
        with self.assertRaisesRegex(ValueError, "differs from current official release"):
            check.require_recorded_candidate_matches_official(official, changed)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.json"
            path.write_text(json.dumps(official))
            self.assertEqual(check.load_candidate(path), official)
            path.write_text('{"schema_version":2,"schema_version":2}')
            with self.assertRaisesRegex(ValueError, "duplicate candidate metadata key"):
                check.load_candidate(path)
            path.unlink()
            try:
                path.symlink_to(Path(directory) / "target.json")
            except OSError:
                pass  # Some native Windows runners disallow creating symlinks.
            else:
                with self.assertRaisesRegex(ValueError, "bounded regular file"):
                    check.load_candidate(path)
                path.unlink()
            path.write_bytes(b" " * (check.MAX_CANDIDATE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "bounded regular file"):
                check.load_candidate(path)

    def test_cli_rejects_changed_branch_metadata_before_downloading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            official = root / "official.json"
            recorded = root / "recorded.json"
            official.write_text(json.dumps(candidate()))
            changed = candidate()
            changed["assets"][1]["id"] += 1
            recorded.write_text(json.dumps(changed))
            argv = ["verify_candidate_asset.py", VERSION, "--candidate", str(official),
                    "--recorded-candidate", str(recorded), "--output", str(root / "result.json")]
            with patch.object(sys, "argv", argv), patch.object(check, "verify",
                    side_effect=AssertionError("download started before metadata equality")):
                with self.assertRaisesRegex(ValueError, "differs from current official release"):
                    check.main()


if __name__ == "__main__":
    unittest.main()
