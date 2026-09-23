import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from check_reproducible_build import check, extract_archive, safe_member_name


class ReproducibilityArchiveTests(unittest.TestCase):
    def test_archive_rejects_path_escape_links_and_case_collisions(self):
        for name in ("../outside", "/absolute", "folder/../outside", "./inside",
                     "folder\\other", "C:/outside"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "unsafe"):
                safe_member_name(tarfile.TarInfo(name))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        with self.assertRaisesRegex(ValueError, "unsafe"):
            safe_member_name(link)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "source.tar"
            with tarfile.open(archive, "w") as output:
                for name in ("readme.md", "README.md"):
                    body = b"fixture"
                    member = tarfile.TarInfo(name)
                    member.size = len(body)
                    output.addfile(member, io.BytesIO(body))
            destination = root / "destination"
            destination.mkdir()
            with self.assertRaisesRegex(ValueError, "case-colliding"):
                extract_archive(archive, destination)
            self.assertEqual(list(destination.iterdir()), [])

    def test_expected_binary_cannot_be_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "binary"
            binary.write_bytes(b"fixture")
            link = root / "link"
            try:
                link.symlink_to(binary)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(ValueError, "regular file"):
                check(link, None)


if __name__ == "__main__":
    unittest.main()
