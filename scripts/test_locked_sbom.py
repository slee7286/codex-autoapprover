import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import locked_sbom


class LockedSbomTests(unittest.TestCase):
    def test_filtered_inventory_requires_root_and_exact_selected_packages(self):
        root_key = ("codex-autoapprover", "0.1.0")
        document = locked_sbom.generate(Path(tempfile.gettempdir()), offline=True,
                                        package_filter={root_key})
        self.assertEqual([(item["name"], item["versionInfo"]) for item in document["packages"]],
                         [root_key])
        with self.assertRaisesRegex(ValueError, "omit the root"):
            locked_sbom.generate(Path(tempfile.gettempdir()), offline=True,
                                 package_filter={("missing", "1.0.0")})
        with self.assertRaisesRegex(ValueError, "differ from Cargo.lock"):
            locked_sbom.generate(Path(tempfile.gettempdir()), offline=True,
                                 package_filter={root_key, ("missing", "1.0.0")})

    def test_locked_archive_digest_and_license_are_verified_before_use(self):
        manifest = b'[package]\nname = "fixture"\nversion = "1.2.3"\nlicense = "MIT/Apache-2.0"\n'
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            member = tarfile.TarInfo("fixture-1.2.3/Cargo.toml")
            member.size = len(manifest)
            archive.addfile(member, io.BytesIO(manifest))
        body = output.getvalue()
        item = {"name": "fixture", "version": "1.2.3", "checksum": locked_sbom.digest(body)}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            path = cache / f"fixture-1.2.3-{item['checksum']}.crate"
            path.write_bytes(body)
            with mock.patch.dict(os.environ, {"CARGO_HOME": str(root / "empty-cargo")}, clear=False):
                accepted = locked_sbom.verified_archive(item, cache, offline=True)
                self.assertEqual(accepted, body)
                self.assertEqual(
                    locked_sbom.license_from_archive(item, accepted),
                    ("MIT OR Apache-2.0", "MIT/Apache-2.0"),
                )
                path.write_bytes(body + b"tamper")
                with self.assertRaisesRegex(ValueError, "differs from Cargo.lock"):
                    locked_sbom.verified_archive(item, cache, offline=True)

    def test_locked_dependency_edges_reject_ambiguous_names(self):
        versions = {"windows-sys": ["0.59.0", "0.61.2"], "serde": ["1.0.229"]}
        self.assertEqual(
            locked_sbom.lock_dependency_id("windows-sys 0.59.0", versions),
            "SPDXRef-Package-windows-sys-0.59.0",
        )
        self.assertEqual(
            locked_sbom.lock_dependency_id("serde", versions),
            "SPDXRef-Package-serde-1.0.229",
        )
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            locked_sbom.lock_dependency_id("windows-sys", versions)
        with self.assertRaisesRegex(ValueError, "unknown"):
            locked_sbom.lock_dependency_id("serde 2.0.0", versions)


if __name__ == "__main__":
    unittest.main()
