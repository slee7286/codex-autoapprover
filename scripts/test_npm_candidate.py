import base64
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

import npm_candidate as npm


VERSION = "0.156.0"


def metadata(alias, package_version, system, cpu, index):
    value = {"name": npm.PACKAGE, "version": package_version,
             "dist": {"tarball": npm.tarball_url(package_version),
                      "integrity": "sha512-" + base64.b64encode(bytes([index]) * 64).decode("ascii")}}
    if system is None:
        value["optionalDependencies"] = npm.expected_optional_dependencies(VERSION)
        value["bin"] = {"codex": "bin/codex.js"}
    else:
        value.update({"os": [system], "cpu": [cpu]})
    return value


def official_records():
    return [npm.package_record(metadata(*item, index), *item, VERSION)
            for index, item in enumerate(npm.aliases(VERSION))]


def candidate():
    return {"codex_version": VERSION, "npm_packages": official_records()}


def lockfile():
    records = official_records()
    packages = {"": {"dependencies": {npm.PACKAGE: VERSION}}}
    for record, (alias, _, system, cpu) in zip(records, npm.aliases(VERSION)):
        entry = {"version": record["version"], "resolved": record["tarball"],
                 "integrity": record["integrity"]}
        if system is None:
            entry["optionalDependencies"] = npm.expected_optional_dependencies(VERSION)
            entry["bin"] = {"codex": "bin/codex.js"}
        else:
            entry.update({"name": npm.PACKAGE, "os": [system], "cpu": [cpu], "optional": True})
        packages[f"node_modules/{alias}"] = entry
    return {"lockfileVersion": 3, "packages": packages}


class NpmCandidateTests(unittest.TestCase):
    def test_official_metadata_fetch_is_bounded_and_pins_all_aliases(self):
        entries = {package_version: metadata(alias, package_version, system, cpu, index)
                   for index, (alias, package_version, system, cpu) in enumerate(npm.aliases(VERSION))}
        requested = []

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

        def open_metadata(request, timeout):
            self.assertEqual(timeout, 30)
            package_version = request.full_url.rsplit("/", 1)[-1]
            requested.append(package_version)
            return Response(request.full_url, json.dumps(entries[package_version]).encode())

        self.assertEqual(npm.fetch_npm_records(VERSION, open_metadata), official_records())
        self.assertEqual(requested, [item[1] for item in npm.aliases(VERSION)])
        with self.assertRaisesRegex(ValueError, "redirect"):
            npm.fetch_metadata(VERSION, lambda request, timeout: Response("https://example.invalid", b"{}"))
        with self.assertRaisesRegex(ValueError, "exceeded limit"):
            npm.fetch_metadata(VERSION, lambda request, timeout:
                               Response(request.full_url, b"x" * (npm.MAX_METADATA_BYTES + 1)))

    def test_changed_npm_identity_and_dependencies_fail_closed(self):
        parent = metadata(*npm.aliases(VERSION)[0], 0)
        variant = metadata(*npm.aliases(VERSION)[4], 4)
        changes = [
            (parent, {"optionalDependencies": {"@openai/codex-linux-x64": "0.156.0"}}),
            (parent, {"dependencies": {"unreviewed": "1.0.0"}}),
            (parent, {"bin": {"codex": "other.js"}}),
            (parent, {"dist": {"tarball": "https://example.invalid/a.tgz",
                               "integrity": parent["dist"]["integrity"]}}),
            (parent, {"dist": {"tarball": parent["dist"]["tarball"],
                               "integrity": "sha512-not-base64"}}),
            (variant, {"os": ["win32"]}),
            (variant, {"cpu": ["arm64"]}),
        ]
        for original, change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                bad = {**original, **change}
                row = npm.aliases(VERSION)[0] if original is parent else npm.aliases(VERSION)[4]
                npm.package_record(bad, *row, VERSION)
        self.assertFalse(npm.valid_integrity("sha512-" + "A" * 86 + "?"))

    def test_lock_requires_exact_root_and_all_recorded_integrities(self):
        baseline = lockfile()
        native = npm.verify_lock(baseline, candidate(), VERSION, "Linux")
        self.assertEqual(native["alias"], "@openai/codex-linux-x64")
        self.assertEqual(npm.verify_lock(baseline, candidate(), VERSION, "Windows")["alias"],
                         "@openai/codex-win32-x64")
        with self.assertRaisesRegex(ValueError, "native Linux or Windows"):
            npm.verify_lock(baseline, candidate(), VERSION, "Darwin")
        changes = [
            lambda lock: lock["packages"][""].update(dependencies={npm.PACKAGE: "^0.156.0"}),
            lambda lock: lock["packages"]["node_modules/@openai/codex-linux-x64"].update(
                integrity="sha512-" + base64.b64encode(b"z" * 64).decode()),
            lambda lock: lock["packages"].update({"node_modules/unreviewed": {}}),
            lambda lock: lock["packages"]["node_modules/@openai/codex"].update(
                optionalDependencies={}),
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                bad = deepcopy(baseline)
                change(bad)
                npm.verify_lock(bad, candidate(), VERSION, "Linux")

    def test_installed_package_set_and_versions_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packages = root / "node_modules" / "@openai"
            for folder, version in (("codex", VERSION), ("codex-linux-x64", VERSION + "-linux-x64")):
                location = packages / folder
                location.mkdir(parents=True)
                manifest = {"name": npm.PACKAGE, "version": version}
                if folder == "codex":
                    manifest["bin"] = {"codex": "bin/codex.js"}
                (location / "package.json").write_text(json.dumps(manifest))
            npm.verify_installed(root, VERSION, "Linux")
            (packages / "codex-linux-x64" / "package.json").write_text(json.dumps(
                {"name": npm.PACKAGE, "version": VERSION + "-win32-x64"}))
            with self.assertRaisesRegex(ValueError, "identity"):
                npm.verify_installed(root, VERSION, "Linux")
            (packages / "unreviewed").mkdir()
            with self.assertRaisesRegex(ValueError, "set differs"):
                npm.verify_installed(root, VERSION, "Linux")


if __name__ == "__main__":
    unittest.main()
