import io
import tarfile
import unittest

import locked_licenses


def crate_archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, body, kind in entries:
            member = tarfile.TarInfo("fixture-1.2.3/" + name)
            if kind == "file":
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
            else:
                member.type = tarfile.SYMTYPE
                member.linkname = "Cargo.toml"
                archive.addfile(member)
    return output.getvalue()


class LockedLicenseTests(unittest.TestCase):
    def test_collects_only_regular_top_level_license_material(self):
        body = crate_archive([
            ("LICENSE-MIT", b"MIT text", "file"),
            ("NOTICE.md", b"notice", "file"),
            ("src/LICENSE", b"nested", "file"),
            ("README.md", b"readme", "file"),
        ])
        self.assertEqual(
            locked_licenses.license_texts({"name": "fixture", "version": "1.2.3"}, body),
            [("LICENSE-MIT", b"MIT text"), ("NOTICE.md", b"notice")],
        )

    def test_duplicate_and_linked_license_members_fail_closed(self):
        for entries in [
            [("LICENSE", b"a", "file"), ("license", b"b", "file")],
            [("LICENSE", b"", "symlink")],
        ]:
            with self.subTest(entries=entries), self.assertRaisesRegex(ValueError, "unsafe"):
                locked_licenses.license_texts(
                    {"name": "fixture", "version": "1.2.3"}, crate_archive(entries)
                )

    def test_bundle_is_deterministic_and_contains_exact_indexed_bytes(self):
        files = {"inventory.json": b"{}\n", "licenses/fixture/1.2.3/LICENSE": b"license\n"}
        first = locked_licenses.bundle(files)
        self.assertEqual(first, locked_licenses.bundle(dict(reversed(list(files.items())))))
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
            self.assertEqual(archive.getnames(), sorted(files))
            for member in archive.getmembers():
                self.assertEqual(member.mode, 0o644)
                self.assertEqual(member.mtime, 0)
                self.assertEqual(archive.extractfile(member).read(), files[member.name])


if __name__ == "__main__":
    unittest.main()
