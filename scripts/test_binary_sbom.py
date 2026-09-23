"""Target-specific build-input selection; synthetic fixtures are not release evidence."""

import copy
from pathlib import Path
import struct
import tempfile
import unittest

import binary_sbom as sbom
from locked_sbom import package_id


REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


class BinarySbomTests(unittest.TestCase):
    def graph_fixture(self, root):
        (root / "Cargo.toml").write_text(
            '[package]\nname = "codex-autoapprover"\nversion = "0.1.0"\n', encoding="utf-8")
        packages = [{"id": "root", "name": "codex-autoapprover", "version": "0.1.0",
                     "source": None, "manifest_path": str(root / "Cargo.toml"),
                     "targets": [{"name": "codex-autoapprover", "kind": ["bin"]}]}]
        packages += [{"id": name, "name": name, "version": "1.0.0", "source": REGISTRY}
                     for name in ("normal", "build", "dev", "transitive")]
        dependency = lambda name, kind: {"pkg": name, "dep_kinds": [{"kind": kind, "target": None}]}
        nodes = [
            {"id": "root", "deps": [dependency("normal", None), dependency("build", "build"),
                                     dependency("dev", "dev")]},
            {"id": "normal", "deps": []},
            {"id": "build", "deps": [dependency("transitive", None)]},
            {"id": "dev", "deps": []},
            {"id": "transitive", "deps": []},
        ]
        metadata = {"workspace_root": str(root), "workspace_members": ["root"],
                    "packages": packages, "resolve": {"root": "root", "nodes": nodes}}
        locked = [{"name": p["name"], "version": p["version"], "source": p["source"]}
                  for p in packages]
        return metadata, locked

    def test_native_graph_excludes_dev_dependencies_and_checks_locked_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata, locked = self.graph_fixture(root)
            keys, edges, root_id = sbom.selected_graph(metadata, locked, root)
            self.assertEqual(keys, {(name, version) for name, version in [
                ("codex-autoapprover", "0.1.0"), ("normal", "1.0.0"),
                ("build", "1.0.0"), ("transitive", "1.0.0")]})
            self.assertEqual(edges, {
                (root_id, package_id("normal", "1.0.0")),
                (root_id, package_id("build", "1.0.0")),
                (package_id("build", "1.0.0"), package_id("transitive", "1.0.0")),
            })
            changed = copy.deepcopy(metadata)
            changed["packages"][1]["source"] = "registry+https://unexpected.example/index"
            with self.assertRaisesRegex(ValueError, "differs from Cargo.lock"):
                sbom.selected_graph(changed, locked, root)

    def test_native_format_check_rejects_other_platform_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            linux = bytearray(20)
            linux[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", linux, 18, 62)
            path = root / "binary"
            path.write_bytes(linux)
            self.assertEqual(sbom.checked_binary(path, "x86_64-unknown-linux-gnu"), linux)
            with self.assertRaisesRegex(ValueError, "format"):
                sbom.checked_binary(path, "x86_64-pc-windows-msvc")
            windows = bytearray(0x46)
            windows[:2] = b"MZ"
            struct.pack_into("<I", windows, 0x3c, 0x40)
            windows[0x40:0x44] = b"PE\0\0"
            struct.pack_into("<H", windows, 0x44, 0x8664)
            path.write_bytes(windows)
            self.assertEqual(sbom.checked_binary(path, "x86_64-pc-windows-msvc"), windows)
            with self.assertRaisesRegex(ValueError, "format"):
                sbom.checked_binary(path, "x86_64-unknown-linux-gnu")
            alias = root / "alias"
            alias.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "symlink"):
                sbom.checked_binary(alias, "x86_64-pc-windows-msvc")

    def test_document_binds_exact_binary_and_refuses_out_of_graph_edges(self):
        root_id = package_id("codex-autoapprover", "0.1.0")
        dependency_id = package_id("normal", "1.0.0")
        keys = {("codex-autoapprover", "0.1.0"), ("normal", "1.0.0")}
        inventory = {"packages": [{"SPDXID": root_id}, {"SPDXID": dependency_id}],
                     "creationInfo": {"created": "2026-09-23T00:00:00Z", "creators": []},
                     "annotations": []}
        doc = sbom.document_for_binary(copy.deepcopy(inventory), keys, {(root_id, dependency_id)},
                                       root_id, "x86_64-unknown-linux-gnu",
                                       "codex-autoapprover-linux-x86_64", "a" * 64, "b" * 64)
        self.assertEqual(doc["files"][0]["checksums"][0]["checksumValue"], "a" * 64)
        self.assertEqual(doc["files"][0]["fileName"], "./codex-autoapprover-linux-x86_64")
        self.assertEqual({item["SPDXID"] for item in doc["packages"]}, {root_id, dependency_id})
        with self.assertRaisesRegex(ValueError, "edge leaves"):
            sbom.document_for_binary(copy.deepcopy(inventory), keys, {(root_id, "SPDXRef-Package-dev-1.0.0")},
                                     root_id, "x86_64-unknown-linux-gnu",
                                     "codex-autoapprover-linux-x86_64", "a" * 64, "b" * 64)


if __name__ == "__main__":
    unittest.main()
