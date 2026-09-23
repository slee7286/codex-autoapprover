#!/usr/bin/env python3
"""Generate a deterministic SPDX inventory of every exact Cargo.lock dependency.

This records the complete locked dependency graph across targets and dev/build
scopes; it is not a binary-specific composition or a legal/security approval.
Every third-party license is read from a source archive whose SHA-256 matches
Cargo.lock. Missing archives may be fetched from the official crates.io host.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
import uuid

from release_gate import source_digest


ROOT = Path(__file__).resolve().parent.parent
MAX_CRATE_BYTES = 50 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
LEGACY_LICENSES = {"Apache-2.0/MIT": "Apache-2.0 OR MIT", "MIT/Apache-2.0": "MIT OR Apache-2.0"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise ValueError(f"crate download redirected: {request.full_url}")


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def archive_url(name: str, version: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or not re.fullmatch(r"[A-Za-z0-9.+-]+", version):
        raise ValueError("invalid locked crate identifier")
    return f"https://static.crates.io/crates/{name}/{name}-{version}.crate"


def verified_archive(package: dict, cache_dir: Path, offline: bool) -> bytes:
    name, version, expected = package["name"], package["version"], package["checksum"]
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError(f"missing locked checksum: {name}@{version}")
    archive_url(name, version)
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    candidates = sorted((cargo_home / "registry/cache").glob(f"*/{name}-{version}.crate"))
    candidates.append(cache_dir / f"{name}-{version}-{expected}.crate")
    for path in candidates:
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_CRATE_BYTES:
            raise ValueError(f"unsafe cached crate: {path}")
        body = path.read_bytes()
        if digest(body) != expected:
            raise ValueError(f"cached crate differs from Cargo.lock: {name}@{version}")
        return body
    if offline:
        raise ValueError(f"locked crate archive unavailable offline: {name}@{version}")
    request = urllib.request.Request(
        archive_url(name, version), headers={"User-Agent": "codex-autoapprover-locked-sbom/0.1"}
    )
    with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
        body = response.read(MAX_CRATE_BYTES + 1)
    if len(body) > MAX_CRATE_BYTES or digest(body) != expected:
        raise ValueError(f"downloaded crate differs from Cargo.lock: {name}@{version}")
    if cache_dir.is_symlink():
        raise ValueError("crate cache directory cannot be a symlink")
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    cache_stat = cache_dir.stat()
    if cache_stat.st_uid != os.geteuid() or stat.S_IMODE(cache_stat.st_mode) & 0o022:
        raise ValueError("crate cache directory must be owner-controlled")
    path = cache_dir / f"{name}-{version}-{expected}.crate"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    created = False
    try:
        with os.fdopen(os.open(path, flags, 0o600), "wb") as output:
            created = True
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        if path.is_symlink() or digest(path.read_bytes()) != expected:
            raise ValueError(f"concurrent crate cache changed: {name}@{version}")
    except BaseException:
        if created:
            path.unlink(missing_ok=True)
        raise
    return body


def license_from_archive(package: dict, body: bytes) -> tuple[str, str | None]:
    name, version = package["name"], package["version"]
    member_name = f"{name}-{version}/Cargo.toml"
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
        matches = [member for member in archive.getmembers() if member.name == member_name]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > MAX_MANIFEST_BYTES:
            raise ValueError(f"missing or unsafe crate manifest: {name}@{version}")
        source = archive.extractfile(matches[0])
        if source is None:
            raise ValueError(f"cannot read crate manifest: {name}@{version}")
        manifest = tomllib.loads(source.read(MAX_MANIFEST_BYTES + 1).decode())
    declared = manifest["package"].get("license")
    if not isinstance(declared, str) or not declared.strip():
        raise ValueError(f"crate lacks declared SPDX license: {name}@{version}")
    return LEGACY_LICENSES.get(declared, declared), declared if declared in LEGACY_LICENSES else None


def package_id(name: str, version: str) -> str:
    return f"SPDXRef-Package-{name}-{version}"


def lock_dependency_id(reference: str, versions: dict[str, list[str]]) -> str:
    parts = reference.split(" ")
    if len(parts) == 2:
        name, version = parts
    elif len(parts) == 1 and len(versions.get(parts[0], [])) == 1:
        name, version = parts[0], versions[parts[0]][0]
    else:
        raise ValueError(f"ambiguous locked dependency: {reference}")
    if version not in versions.get(name, []):
        raise ValueError(f"unknown locked dependency: {reference}")
    return package_id(name, version)


def generate(cache_dir: Path, offline: bool) -> dict:
    lock_body = (ROOT / "Cargo.lock").read_bytes()
    locked = tomllib.loads(lock_body.decode())["package"]
    root_manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    versions: dict[str, list[str]] = {}
    for package in locked:
        versions.setdefault(package["name"], []).append(package["version"])
    root_matches = [p for p in locked if p["name"] == root_manifest["name"] and p["version"] == root_manifest["version"]]
    if len(root_matches) != 1 or root_manifest.get("license") != "MIT":
        raise ValueError("local package identity or license differs from Cargo.lock")
    packages = []
    relationships = []
    for item in sorted(locked, key=lambda p: (p["name"], p["version"])):
        name, version = item["name"], item["version"]
        is_root = name == root_manifest["name"] and version == root_manifest["version"]
        if is_root:
            declared, original = "MIT", None
            location = "NOASSERTION"
        else:
            if item.get("source") != REGISTRY_SOURCE:
                raise ValueError(f"unsupported locked registry source: {name}@{version}")
            declared, original = license_from_archive(item, verified_archive(item, cache_dir, offline))
            location = archive_url(name, version)
        entry = {
            "name": name,
            "SPDXID": package_id(name, version),
            "versionInfo": version,
            "downloadLocation": location,
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": declared,
            "copyrightText": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:cargo/{name}@{version}",
            }],
        }
        if not is_root:
            entry["checksums"] = [{"algorithm": "SHA256", "checksumValue": item["checksum"]}]
        if original is not None:
            entry["comment"] = f"Normalized legacy Cargo license expression: {original}"
        packages.append(entry)
        for reference in item.get("dependencies", []):
            relationships.append({
                "spdxElementId": entry["SPDXID"],
                "relatedSpdxElement": lock_dependency_id(reference, versions),
                "relationshipType": "DEPENDS_ON",
            })
    relationships.append({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": package_id(root_manifest["name"], root_manifest["version"]),
        "relationshipType": "DESCRIBES",
    })
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or subprocess.check_output(
        ["git", "log", "-1", "--format=%ct"], cwd=ROOT, text=True).strip())
    created = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    source_sha = source_digest(ROOT)
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"codex-autoapprover-{root_manifest['version']}-locked-dependencies",
        "documentNamespace": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'{source_sha}:{epoch}')}",
        "creationInfo": {"created": created, "creators": ["Tool: scripts/locked_sbom.py"]},
        "comment": "Complete Cargo.lock graph across target/dev/build scopes; not binary-specific composition or license/security approval.",
        "documentDescribes": [package_id(root_manifest["name"], root_manifest["version"])],
        "packages": packages,
        "relationships": sorted(relationships, key=lambda r: (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"])),
        "annotations": [{
            "annotationDate": created,
            "annotationType": "OTHER",
            "annotator": "Tool: scripts/locked_sbom.py",
            "comment": f"Cargo.lock SHA-256: {digest(lock_body)}; source SHA-256: {source_sha}",
        }],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, default=Path(tempfile.gettempdir()) / "codex-autoapprover-crates")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = generate(args.cache_dir, args.offline)
    body = (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()
    if args.output.exists() or args.output.is_symlink():
        if args.output.is_symlink() or args.output.read_bytes() != body:
            raise ValueError("existing SBOM differs; use a clean output path")
    else:
        args.output.write_bytes(body)
    print(f"Locked dependency SPDX inventory: {args.output} ({len(document['packages'])} packages)")
    print(f"SHA-256: {digest(body)}")


if __name__ == "__main__":
    main()
