#!/usr/bin/env python3
"""Create a deterministic, explicitly unqualified Linux development archive.

This is a packaging rehearsal. A production release also requires the native
evidence gate, independently authenticated checksums and signed provenance.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import tarfile
import tomllib

from release_gate import source_digest


ROOT = Path(__file__).resolve().parent.parent
FILE_LIMIT = 2 * 1024 * 1024 * 1024
CONTENTS = {
    "compatibility/manifest.json": (ROOT / "compatibility/manifest.json", 0o644),
    "scripts/install-linux.sh": (ROOT / "scripts/install-linux.sh", 0o755),
    "LICENSE": (ROOT / "LICENSE", 0o644),
    "README.md": (ROOT / "README.md", 0o644),
}


def checked_bytes(path: Path, require_single_link: bool = True) -> bytes:
    before = path.stat()
    if path.is_symlink() or not path.is_file() or (require_single_link and before.st_nlink != 1):
        raise ValueError(f"not a permitted regular file: {path}")
    if before.st_size > FILE_LIMIT:
        raise ValueError(f"file exceeds package limit: {path}")
    body = path.read_bytes()
    after = path.stat()
    stamp = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if len(body) != before.st_size or stamp(before) != stamp(after):
        raise ValueError(f"file changed while packaging: {path}")
    return body


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def add_bytes(archive: tarfile.TarFile, name: str, body: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(body)
    info.mode = mode
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    archive.addfile(info, io.BytesIO(body))


def package(binary: Path, output_dir: Path) -> tuple[Path, str]:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "aarch64"}:
        raise ValueError("native Linux x86_64 or aarch64 packaging host required")
    if binary.is_symlink():
        raise ValueError("binary input cannot be a symlink")
    binary = binary.resolve(strict=True)
    before_source = source_digest(ROOT)
    body = checked_bytes(binary, require_single_link=False)
    if not body.startswith(b"\x7fELF"):
        raise ValueError("input is not a native Linux ELF executable")
    manifest = checked_bytes(ROOT / "compatibility/manifest.json")
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    if json.loads(manifest)["autoapprover_version"] != version:
        raise ValueError("manifest and Cargo package versions differ")
    subprocess.run(
        [str(binary), "verify-manifest", "--manifest", str(ROOT / "compatibility/manifest.json")],
        check=True, timeout=15, stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["python3", str(ROOT / "scripts/release_gate.py"), "--binary", str(binary)],
        check=True, timeout=15, stdout=subprocess.DEVNULL,
    )
    if sha256(checked_bytes(binary, require_single_link=False)) != sha256(body):
        raise ValueError("binary changed after verification")
    artifact_name = f"codex-autoapprover-{version}-linux-{platform.machine()}-dev"
    files = {"bin/codex-autoapprover": (body, 0o755)}
    for name, (path, mode) in CONTENTS.items():
        files[name] = (checked_bytes(path), mode)
    metadata = {
        "schema_version": 1,
        "release_status": "unqualified-development-rehearsal",
        "autoapprover_version": version,
        "platform": f"linux-{platform.machine()}",
        "binary_sha256": sha256(body),
        "manifest_sha256": sha256(manifest),
        "source_sha256": before_source,
        "file_sha256": {name: sha256(data) for name, (data, _) in sorted(files.items())},
    }
    if source_digest(ROOT) != before_source:
        raise ValueError("source changed while packaging")
    for name, (path, _) in CONTENTS.items():
        if checked_bytes(path) != files[name][0]:
            raise ValueError(f"package file changed while packaging: {name}")
    files["artifact.json"] = ((json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode(), 0o644)
    if output_dir.is_symlink():
        raise ValueError("output directory cannot be a symlink")
    output_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    output_stat = output_dir.stat()
    if output_stat.st_uid != os.geteuid() or stat.S_IMODE(output_stat.st_mode) & 0o022:
        raise ValueError("output directory must be owner-controlled")
    path = output_dir / f"{artifact_name}.tar.gz"
    temp = output_dir / f".{artifact_name}.{os.getpid()}.tmp"
    try:
        with temp.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as zipped:
                with tarfile.open(fileobj=zipped, mode="w", format=tarfile.GNU_FORMAT) as archive:
                    for name, (data, mode) in sorted(files.items()):
                        add_bytes(archive, f"{artifact_name}/{name}", data, mode)
            raw.flush()
            os.fsync(raw.fileno())
        if path.exists() or path.is_symlink():
            if checked_bytes(path) != checked_bytes(temp):
                raise ValueError("existing archive differs; use a clean output directory")
        else:
            os.link(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    digest = sha256(checked_bytes(path))
    checksum_path = output_dir / f"{path.name}.sha256"
    expected_checksum = f"{digest}  {path.name}\n"
    if checksum_path.exists() or checksum_path.is_symlink():
        if checked_bytes(checksum_path) != expected_checksum.encode():
            raise ValueError("existing checksum differs; use a clean output directory")
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        with os.fdopen(os.open(checksum_path, flags, 0o644), "w") as checksum_file:
            checksum_file.write(expected_checksum)
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
