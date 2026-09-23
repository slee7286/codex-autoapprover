import io
import struct
import unittest
import zipfile

from package_windows import archive_bytes, is_x64_pe


class WindowsDevelopmentArchiveTests(unittest.TestCase):
    def test_archive_is_reproducible_and_extracts_exact_bytes(self):
        expected = {"LICENSE": b"license\n", "bin/codex-autoapprover.exe": b"MZ\0test"}
        first = archive_bytes("sample", expected)
        second = archive_bytes("sample", dict(reversed(list(expected.items()))))
        self.assertEqual(first, second)
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            self.assertEqual(archive.namelist(), [f"sample/{name}" for name in sorted(expected)])
            for name, body in expected.items():
                self.assertEqual(archive.read(f"sample/{name}"), body)
            self.assertTrue(all(info.date_time == (1980, 1, 1, 0, 0, 0)
                                for info in archive.infolist()))

    def test_only_x64_pe_header_can_enter_windows_package(self):
        body = bytearray(0x86)
        body[:2] = b"MZ"
        struct.pack_into("<I", body, 0x3C, 0x80)
        body[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", body, 0x84, 0x8664)
        self.assertTrue(is_x64_pe(body))
        struct.pack_into("<H", body, 0x84, 0x14C)
        self.assertFalse(is_x64_pe(body))
        self.assertFalse(is_x64_pe(body[:0x82]))


if __name__ == "__main__":
    unittest.main()
