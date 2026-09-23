#!/usr/bin/env python3
"""Bind a native release binary to its target-specific Cargo build inputs.

The SPDX document covers normal and build dependencies selected for one native
target, including proc macros. It excludes dev-only and other-target packages.
It is not a measurement of linked code, a compiler/OS inventory, or a security
or license approval. The executable digest and source digest make its scope
reviewable alongside native provenance and release evidence.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import stat
import struct
import subprocess
import tempfile
import tomllib
import uuid

from cargo_graph import selected_graph
from locked_sbom import ROOT, generate as locked_inventory, package_id
from release_gate import load_json, source_digest, validate_manifest


TARGETS = {
    "x86_64-unknown-linux-gnu": ("Linux", "codex-autoapprover-linux-x86_64"),
    "x86_64-pc-windows-msvc": ("Windows", "codex-autoapprover-windows-x86_64.exe"),
}
FILE_ID = "SPDXRef-File-ConsumerBinary"
FILE_LIMIT = 2 * 1024 * 1024 * 1024
SBOM_LIMIT = 16 * 1024 * 1024


def native_target() -> tuple[str, str]:
    result = subprocess.run(["rustc", "-vV"], check=True, capture_output=True,
                            text=True, timeout=10)
    hosts = [line.removeprefix("host: ") for line in result.stdout.splitlines()
             if line.startswith("host: ")]
    if len(hosts) != 1 or hosts[0] not in TARGETS or platform.system() != TARGETS[hosts[0]][0]:
        raise ValueError("native supported Linux/Windows x86_64 Rust host required")
    return hosts[0], TARGETS[hosts[0]][1]


def checked_binary(path: Path, target: str) -> bytes:
    if target not in TARGETS:
        raise ValueError("unsupported native binary target")
    if path.is_symlink():
        raise ValueError("binary cannot be a symlink")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= FILE_LIMIT:
        raise ValueError("binary must be a bounded regular file")
    body = path.read_bytes()
    after = path.stat()
    stamp = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if len(body) != before.st_size or stamp(before) != stamp(after):
        raise ValueError("binary changed while being inspected")
    if target == "x86_64-unknown-linux-gnu":
        valid = (len(body) >= 20 and body[:6] == b"\x7fELF\x02\x01"
                 and struct.unpack_from("<H", body, 18)[0] == 62)
    else:
        offset = struct.unpack_from("<I", body, 0x3c)[0] if len(body) >= 0x40 else len(body)
        valid = (body[:2] == b"MZ" and offset + 6 <= len(body)
                 and body[offset:offset + 4] == b"PE\0\0"
                 and struct.unpack_from("<H", body, offset + 4)[0] == 0x8664)
    if not valid:
        raise ValueError("binary format does not match the native target")
    return body


def document_for_binary(inventory: dict, keys: set[tuple[str, str]],
                        edges: set[tuple[str, str]], root_id: str, target: str,
                        artifact_name: str, binary_sha: str, source_sha: str) -> dict:
    selected_ids = {package_id(name, version) for name, version in keys}
    packages = [package for package in inventory["packages"] if package["SPDXID"] in selected_ids]
    if {package["SPDXID"] for package in packages} != selected_ids or root_id not in selected_ids:
        raise ValueError("SPDX packages differ from native Cargo graph")
    if any(parent not in selected_ids or child not in selected_ids for parent, child in edges):
        raise ValueError("SPDX dependency edge leaves the selected graph")
    created = inventory["creationInfo"]["created"]
    inventory["name"] = f"codex-autoapprover-{target}-binary-build-inputs"
    inventory["documentNamespace"] = "urn:uuid:" + str(uuid.uuid5(
        uuid.NAMESPACE_URL, f"{source_sha}:{target}:{binary_sha}:{created}:binary-build-inputs"))
    inventory["comment"] = (
        "Native target-specific normal and build dependency closure for the digest-bound consumer "
        "executable. Includes proc-macro build inputs; excludes dev-only and other-target crates. "
        "Compiler, standard library, OS components and exact linked-code composition are not "
        "enumerated. This is not provenance, vulnerability clearance or license approval."
    )
    inventory["creationInfo"]["creators"].append("Tool: scripts/binary_sbom.py")
    inventory["packages"] = packages
    inventory["documentDescribes"] = [root_id, FILE_ID]
    inventory["files"] = [{
        "fileName": f"./{artifact_name}",
        "SPDXID": FILE_ID,
        "checksums": [{"algorithm": "SHA256", "checksumValue": binary_sha}],
        "fileTypes": ["BINARY"],
        "licenseConcluded": "NOASSERTION",
        "licenseInfoInFiles": ["NOASSERTION"],
        "copyrightText": "NOASSERTION",
    }]
    inventory["relationships"] = sorted(
        [{"spdxElementId": parent, "relatedSpdxElement": child,
          "relationshipType": "DEPENDS_ON"} for parent, child in edges]
        + [{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": described,
            "relationshipType": "DESCRIBES"} for described in (root_id, FILE_ID)],
        key=lambda item: (item["spdxElementId"], item["relationshipType"], item["relatedSpdxElement"]),
    )
    inventory["annotations"].append({
        "annotationDate": created,
        "annotationType": "OTHER",
        "annotator": "Tool: scripts/binary_sbom.py",
        "comment": f"Native Rust target: {target}; consumer executable SHA-256: {binary_sha}; source SHA-256: {source_sha}",
    })
    return inventory


def generate(binary: Path, cache_dir: Path, offline: bool) -> dict:
    target, artifact_name = native_target()
    source_before = source_digest(ROOT)
    binary_before = hashlib.sha256(checked_binary(binary, target)).hexdigest()
    result = subprocess.run([str(binary.resolve(strict=True)), "support-matrix"], check=True,
                            capture_output=True, timeout=10)
    if len(result.stdout) > 4 * 1024 * 1024:
        raise ValueError("binary support matrix exceeds limit")
    embedded = load_json(result.stdout)
    source_manifest = load_json((ROOT / "compatibility/manifest.json").read_bytes())
    validate_manifest(embedded)
    if embedded != source_manifest:
        raise ValueError("binary embeds a different compatibility manifest")
    command = ["cargo", "metadata", "--locked", "--format-version", "1",
               "--filter-platform", target]
    if offline:
        command.append("--offline")
    metadata = json.loads(subprocess.run(command, cwd=ROOT, check=True, capture_output=True,
                                         timeout=90).stdout)
    locked = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))["package"]
    keys, edges, root_id = selected_graph(metadata, locked, ROOT)
    inventory = locked_inventory(cache_dir, offline, package_filter=keys)
    document = document_for_binary(inventory, keys, edges, root_id, target, artifact_name,
                                   binary_before, source_before)
    if source_digest(ROOT) != source_before or hashlib.sha256(checked_binary(binary, target)).hexdigest() != binary_before:
        raise ValueError("binary or source changed while generating SBOM")
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path,
                        default=Path(tempfile.gettempdir()) / "codex-autoapprover-crates")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    document = generate(args.binary, args.cache_dir, args.offline)
    body = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
    if len(body) > SBOM_LIMIT:
        raise ValueError("binary SBOM exceeds attestation size limit")
    if args.output.exists() or args.output.is_symlink():
        if args.output.is_symlink() or args.output.read_bytes() != body:
            raise ValueError("existing binary SBOM differs from native source or executable")
    else:
        args.output.write_bytes(body)
    print(f"Native binary build-input SPDX SBOM: {args.output} ({len(document['packages'])} packages)")
    print(f"SHA-256: {hashlib.sha256(body).hexdigest()}")


if __name__ == "__main__":
    main()
