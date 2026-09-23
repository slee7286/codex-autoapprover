#!/usr/bin/env python3
"""Verify one official native release download; this never certifies support."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import urllib.parse
import urllib.request

from watch_codex import REQUIRED_ASSETS, version_key


ASSET_BY_OS = {"Linux": REQUIRED_ASSETS[0], "Windows": REQUIRED_ASSETS[1]}
FINAL_HOSTS = {"github.com", "release-assets.githubusercontent.com"}
MAX_DOWNLOAD = 2 * 1024**3
CHUNK = 1024 * 1024
MAX_CANDIDATE_BYTES = 1024 * 1024


class AllowedAssetRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        target = urllib.parse.urlparse(newurl)
        if target.scheme != "https" or target.hostname not in FINAL_HOSTS:
            raise ValueError("unexpected release asset redirect")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate candidate metadata key")
        result[key] = value
    return result


def load_candidate(path):
    entry = os.lstat(path)
    if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1
            or entry.st_size > MAX_CANDIDATE_BYTES):
        raise ValueError("candidate metadata must be a bounded regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    with os.fdopen(os.open(path, flags), "rb") as source:
        before = os.fstat(source.fileno())
        if ((before.st_dev, before.st_ino) != (entry.st_dev, entry.st_ino)
                or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > MAX_CANDIDATE_BYTES):
            raise ValueError("candidate metadata changed before inspection")
        body = source.read(MAX_CANDIDATE_BYTES + 1)
        after = os.fstat(source.fileno())
        if (len(body) != before.st_size or (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError("candidate metadata changed during inspection")
    return json.loads(body, object_pairs_hook=unique_object)


def require_recorded_candidate_matches_official(official, recorded):
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"),
                                       allow_nan=False)
    if canonical(recorded) != canonical(official):
        raise ValueError("candidate branch metadata differs from current official release")


def selected_asset(candidate, system, version):
    version_key(version)
    if system not in ASSET_BY_OS:
        raise ValueError("candidate asset verification requires native Linux or Windows")
    tag = f"rust-v{version}"
    if (not isinstance(candidate, dict) or type(candidate.get("schema_version")) is not int
            or candidate["schema_version"] != 2 or candidate.get("codex_version") != version
            or candidate.get("upstream_tag") != tag
            or candidate.get("required_platforms") != ["linux-x86_64", "windows-x86_64"]
            or candidate.get("status") != "unverified"):
        raise ValueError("candidate metadata does not match the selected version")
    name = ASSET_BY_OS[system]
    assets = candidate.get("assets")
    if not isinstance(assets, list) or len(assets) != len(REQUIRED_ASSETS):
        raise ValueError("candidate has incomplete native asset metadata")
    if any(not isinstance(asset, dict) or not isinstance(asset.get("name"), str) for asset in assets):
        raise ValueError("candidate has malformed native assets")
    matching = [asset for asset in assets if asset["name"] == name]
    if len(matching) != 1 or {asset["name"] for asset in assets} != set(REQUIRED_ASSETS):
        raise ValueError("candidate has ambiguous native assets")
    asset = matching[0]
    url = f"https://github.com/openai/codex/releases/download/{tag}/{name}"
    if (asset.get("url") != url or type(asset.get("size")) is not int
            or not 0 < asset["size"] <= MAX_DOWNLOAD
            or type(asset.get("id")) is not int or asset["id"] <= 0
            or not isinstance(asset.get("digest"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", asset["digest"]) is None):
        raise ValueError("candidate native asset identity is invalid")
    return asset


def verify(candidate, system, version, open_url=None):
    asset = selected_asset(candidate, system, version)
    open_url = open_url or urllib.request.build_opener(AllowedAssetRedirect()).open
    request = urllib.request.Request(asset["url"], headers={"User-Agent": "codex-autoapprover-asset-check"})
    count = 0
    digest = hashlib.sha256()
    with open_url(request, timeout=60) as response:
        final = urllib.parse.urlparse(response.geturl())
        if final.scheme != "https" or final.hostname not in FINAL_HOSTS:
            raise ValueError("unexpected release asset redirect")
        while True:
            chunk = response.read(CHUNK)
            if not chunk:
                break
            count += len(chunk)
            if count > asset["size"] or count > MAX_DOWNLOAD:
                raise ValueError("release asset exceeds its declared size")
            digest.update(chunk)
    actual = digest.hexdigest()
    if count != asset["size"] or f"sha256:{actual}" != asset["digest"]:
        raise ValueError("release asset size or SHA-256 differs from official metadata")
    return {"schema_version": 1, "codex_version": version, "os": system,
            "asset_name": asset["name"], "asset_id": asset["id"],
            "size": count, "sha256": actual,
            "status": "native-download-integrity-only", "certified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--candidate", type=Path, default=Path("candidate-runner.json"))
    parser.add_argument("--recorded-candidate", type=Path,
                        help="Require checked-out candidate branch metadata to match the refreshed official record")
    parser.add_argument("--output", type=Path, default=Path("asset-verification.json"))
    args = parser.parse_args()
    candidate = load_candidate(args.candidate)
    if args.recorded_candidate:
        require_recorded_candidate_matches_official(candidate, load_candidate(args.recorded_candidate))
    result = verify(candidate, platform.system(), args.version)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
