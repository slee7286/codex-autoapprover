"""Repair-tool integrity fixtures; they do not qualify approval compatibility."""

import json
from pathlib import Path
import tempfile
import unittest

from npm_candidate import PACKAGE
from test_npm_candidate import VERSION, lockfile, official_records
from verify_repair_cli import verify


class RepairCliIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = {
            "name": "codex-autoapprover-repair-cli", "version": "0.0.0",
            "private": True, "dependencies": {PACKAGE: VERSION},
        }
        self.lock = lockfile()
        self.lock.update(name=self.package["name"], version=self.package["version"])
        self.lock["packages"][""] = {
            "name": self.package["name"], "version": self.package["version"],
            "dependencies": {PACKAGE: VERSION},
        }
        self.write()

    def write(self):
        (self.root / "package.json").write_text(json.dumps(self.package))
        (self.root / "package-lock.json").write_text(json.dumps(self.lock))

    def test_pinned_lock_matches_official_records_and_requires_an_install_when_requested(self):
        self.assertEqual(verify(self.root, system="Linux", records=official_records()), VERSION)
        with self.assertRaisesRegex(ValueError, "installed npm package set"):
            verify(self.root, installed=True, system="Linux", records=official_records())

    def test_changed_manifest_lock_or_official_integrity_is_rejected(self):
        self.package["scripts"] = {"postinstall": "echo unsafe"}
        self.write()
        with self.assertRaisesRegex(ValueError, "manifest differs"):
            verify(self.root, system="Linux", records=official_records())
        del self.package["scripts"]
        self.lock["packages"]["node_modules/@openai/codex"]["integrity"] = "sha512-invalid"
        self.write()
        with self.assertRaisesRegex(ValueError, "integrity"):
            verify(self.root, system="Linux", records=official_records())


if __name__ == "__main__":
    unittest.main()
