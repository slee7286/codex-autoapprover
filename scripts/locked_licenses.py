#!/usr/bin/env python3
"""Bundle available license texts from checksum-verified Cargo.lock archives.

This reads only locally cached, checksum-verified archives. It is review
material for the complete locked graph, not a legal conclusion or a
binary-specific notice list. Missing license files remain explicit.
"""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile
import tomllib

from locked_sbom import ROOT, REGISTRY_SOURCE, license_from_archive, verified_archive
from release_gate import source_digest


LICENSE_NAME = re.compile(r"(?:LICENSE|LICENCE|COPYING|NOTICE)(?:[._-][^/]*)?\Z", re.IGNORECASE)
MAX_TEXT_BYTES = 1024 * 1024
MAX_MEMBERS = 50_000


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def license_texts(package, body):
    prefix = f"{package['name']}-{package['version']}/"
    found = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ValueError("crate archive contains too many members")
        for member in members:
            if not member.name.startswith(prefix):
                continue
            name = member.name[len(prefix):]
            if not LICENSE_NAME.fullmatch(name):
                continue
            folded = name.casefold()
            if folded in found or not member.isfile() or member.size > MAX_TEXT_BYTES:
                raise ValueError(f"duplicate or unsafe crate license text: {package['name']}@{package['version']}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("crate license text could not be read")
            text = stream.read(MAX_TEXT_BYTES + 1)
            if len(text) != member.size:
                raise ValueError("crate license text length changed")
            found[folded] = (name, text)
    return [found[key] for key in sorted(found)]


def material(cache_dir):
    locked_bytes = (ROOT / "Cargo.lock").read_bytes()
    locked = tomllib.loads(locked_bytes.decode())["package"]
    root = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    root_matches = [p for p in locked if p["name"] == root["name"] and p["version"] == root["version"]]
    if len(root_matches) != 1 or root.get("license") != "MIT":
        raise ValueError("root package identity or license differs from Cargo.lock")
    files = {}
    packages = []
    missing = []
    for package in sorted(locked, key=lambda item: (item["name"], item["version"])):
        name, version = package["name"], package["version"]
        is_root = name == root["name"] and version == root["version"]
        if is_root:
            declared = "MIT"
            texts = [("LICENSE", (ROOT / "LICENSE").read_bytes())]
            archive_digest = None
        else:
            if package.get("source") != REGISTRY_SOURCE:
                raise ValueError(f"unsupported locked source: {name}@{version}")
            body = verified_archive(package, cache_dir, offline=True)
            declared, _ = license_from_archive(package, body)
            texts = license_texts(package, body)
            archive_digest = package["checksum"]
        records = []
        for filename, body in texts:
            path = f"licenses/{name}/{version}/{filename}"
            if path in files:
                raise ValueError("duplicate license bundle path")
            files[path] = body
            records.append({"path": path, "sha256": sha256(body), "size": len(body)})
        if not records:
            missing.append(f"{name}@{version}")
        record = {"name": name, "version": version, "declared_license": declared,
                  "license_files": records}
        if archive_digest is not None:
            record["crate_sha256"] = archive_digest
        packages.append(record)
    inventory = {
        "schema_version": 1,
        "status": "preliminary-locked-license-material-not-legal-approval",
        "source_sha256": source_digest(ROOT),
        "cargo_lock_sha256": sha256(locked_bytes),
        "packages": packages,
        "packages_without_top_level_license_text": missing,
    }
    files["inventory.json"] = (json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode()
    return inventory, files


def bundle(files):
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=9) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for path, body in sorted(files.items()):
                entry = tarfile.TarInfo(path)
                entry.size = len(body)
                entry.mode = 0o644
                entry.mtime = 0
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                archive.addfile(entry, io.BytesIO(body))
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path,
                        default=Path(tempfile.gettempdir()) / "codex-autoapprover-crates")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inventory, files = material(args.cache_dir)
    body = bundle(files)
    if args.output.exists() or args.output.is_symlink():
        if args.output.is_symlink() or args.output.read_bytes() != body:
            raise ValueError("existing license bundle differs; use a clean output path")
    else:
        args.output.write_bytes(body)
    print(f"Preliminary locked license bundle: {args.output} ({len(inventory['packages'])} packages)")
    print(f"Missing top-level texts: {', '.join(inventory['packages_without_top_level_license_text']) or 'none'}")
    print(f"SHA-256: {sha256(body)}")


if __name__ == "__main__":
    main()
