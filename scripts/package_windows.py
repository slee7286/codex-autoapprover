#!/usr/bin/env python3
"""Create a deterministic, explicitly unqualified Windows development archive."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import stat
import struct
import subprocess
import sys
import tomllib
import zipfile

from release_gate import source_digest


ROOT = Path(__file__).resolve().parent.parent
FILE_LIMIT = 2 * 1024 * 1024 * 1024
CONTENTS = {
    "compatibility/manifest.json": ROOT / "compatibility/manifest.json",
    "scripts/install-windows-artifact.ps1": ROOT / "scripts/install-windows-artifact.ps1",
    "LICENSE": ROOT / "LICENSE",
    "README.md": ROOT / "README.md",
}


def checked_bytes(path: Path) -> bytes:
    before = path.stat(follow_symlinks=False)
    attributes = getattr(before, "st_file_attributes", 0)
    if not stat.S_ISREG(before.st_mode) or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        raise ValueError(f"not a permitted regular file: {path}")
    if before.st_size > FILE_LIMIT:
        raise ValueError(f"file exceeds package limit: {path}")
    body = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    stamp = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if len(body) != before.st_size or stamp(before) != stamp(after):
        raise ValueError(f"file changed while packaging: {path}")
    return body


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def is_x64_pe(body: bytes) -> bool:
    if len(body) < 0x40 or body[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", body, 0x3C)[0]
    return offset + 6 <= len(body) and body[offset:offset + 4] == b"PE\0\0" and struct.unpack_from("<H", body, offset + 4)[0] == 0x8664


def archive_bytes(name: str, files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for relative, body in sorted(files.items()):
            info = zipfile.ZipInfo(f"{name}/{relative}", date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100644 << 16)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, body)
    return output.getvalue()


def write_once(path: Path, body: bytes) -> None:
    if path.exists() or path.is_symlink():
        if checked_bytes(path) != body:
            raise ValueError(f"existing output differs; use a clean directory: {path}")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(path, flags, 0o600), "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())


def package(binary: Path, output_dir: Path) -> tuple[Path, str]:
    if platform.system() != "Windows" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise ValueError("native Windows x86_64 packaging host required")
    if binary.is_symlink():
        raise ValueError("binary input cannot be a symlink")
    binary = binary.resolve(strict=True)
    before_source = source_digest(ROOT)
    body = checked_bytes(binary)
    if not is_x64_pe(body):
        raise ValueError("input is not a Windows x86_64 PE executable")
    manifest = checked_bytes(ROOT / "compatibility/manifest.json")
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    if json.loads(manifest)["autoapprover_version"] != version:
        raise ValueError("manifest and Cargo package versions differ")
    subprocess.run(
        [str(binary), "verify-manifest", "--manifest", str(ROOT / "compatibility/manifest.json")],
        check=True, timeout=15, stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/release_gate.py"), "--binary", str(binary)],
        check=True, timeout=15, stdout=subprocess.DEVNULL,
    )
    if sha256(checked_bytes(binary)) != sha256(body):
        raise ValueError("binary changed after verification")
    name = f"codex-autoapprover-{version}-windows-x86_64-dev"
    files = {"bin/codex-autoapprover.exe": body}
    for relative, path in CONTENTS.items():
        files[relative] = checked_bytes(path)
    metadata = {
        "schema_version": 1,
        "release_status": "unqualified-development-rehearsal",
        "autoapprover_version": version,
        "platform": "windows-x86_64",
        "binary_sha256": sha256(body),
        "manifest_sha256": sha256(manifest),
        "source_sha256": before_source,
        "file_sha256": {relative: sha256(data) for relative, data in sorted(files.items())},
    }
    if source_digest(ROOT) != before_source:
        raise ValueError("source changed while packaging")
    for relative, path in CONTENTS.items():
        if checked_bytes(path) != files[relative]:
            raise ValueError(f"package file changed while packaging: {relative}")
    files["artifact.json"] = (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode()
    if output_dir.is_symlink():
        raise ValueError("output directory cannot be a symlink")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_stat = output_dir.stat(follow_symlinks=False)
    if not stat.S_ISDIR(output_stat.st_mode) or getattr(output_stat, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        raise ValueError("output directory cannot be a reparse point")
    path = output_dir / f"{name}.zip"
    zipped = archive_bytes(name, files)
    write_once(path, zipped)
    digest = sha256(checked_bytes(path))
    write_once(output_dir / f"{path.name}.sha256", f"{digest}  {path.name}\n".encode("ascii"))
    return path, digest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    path, digest = package(args.binary, args.output_dir)
    print(f"Unqualified development archive: {path}")
    print(f"SHA-256: {digest}")


if __name__ == "__main__":
    main()
