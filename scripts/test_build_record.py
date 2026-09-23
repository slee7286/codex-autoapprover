"""Native build-observation tamper checks; synthetic bytes are not release evidence."""

from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import build_record


class BuildRecordTests(unittest.TestCase):
    def test_binary_source_and_toolchain_changes_invalidate_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.lock").write_bytes(b"locked packages")
            (root / "compatibility").mkdir()
            (root / "compatibility/manifest.json").write_bytes(b"{}")
            binary = root / "candidate"
            image = bytearray(20)
            image[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", image, 18, 62)
            binary.write_bytes(image)
            rustc = "rustc 1.98.0\nhost: x86_64-unknown-linux-gnu"
            tool_output = lambda command, limit=4096: rustc if command[0] == "rustc" else "cargo 1.98.0"
            with patch.object(build_record, "ROOT", root), \
                 patch.object(build_record, "native_target", return_value=("x86_64-unknown-linux-gnu", "candidate")), \
                 patch.object(build_record, "source_digest", return_value="a" * 64), \
                 patch.object(build_record, "git_identity", return_value=("b" * 40, True)), \
                 patch.object(build_record, "command_output", side_effect=tool_output), \
                 patch.object(build_record, "host_facts", return_value={
                     "system": "Linux", "release": "7.0", "version": "test",
                     "machine": "x86_64", "distribution_id": "ubuntu", "distribution_version": "24.04",
                 }):
                record = build_record.make_record(binary, require_clean=True)
                build_record.validate_record(record, binary, require_clean=True)
                binary.write_bytes(image + b"changed")
                with self.assertRaisesRegex(ValueError, "differs from binary or source"):
                    build_record.validate_record(record, binary, require_clean=True)
                binary.write_bytes(image)
                with patch.object(build_record, "source_digest", return_value="c" * 64):
                    with self.assertRaisesRegex(ValueError, "differs from binary or source"):
                        build_record.validate_record(record, binary, require_clean=True)
                with patch.object(build_record, "command_output", return_value="rustc changed"):
                    with self.assertRaisesRegex(ValueError, "toolchain differs"):
                        build_record.validate_record(record, binary, require_clean=True)

    def test_record_requires_a_clean_build_tree_for_workflow_use(self):
        with patch.object(build_record, "native_target", return_value=("x86_64-unknown-linux-gnu", "candidate")), \
             patch.object(build_record, "source_digest", return_value="a" * 64), \
             patch.object(build_record, "checked_binary", return_value=b"binary"), \
             patch.object(build_record, "git_identity", return_value=("b" * 40, False)):
            with self.assertRaisesRegex(ValueError, "dirty"):
                build_record.make_record(Path("candidate"), require_clean=True)


if __name__ == "__main__":
    unittest.main()
