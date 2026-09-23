"""Pin official npm Codex packages without treating a candidate as certified."""

import base64
import json
from pathlib import Path
import re
import urllib.request


PACKAGE = "@openai/codex"
REGISTRY = "https://registry.npmjs.org"
MAX_METADATA_BYTES = 1024 * 1024
VARIANTS = (
    ("darwin-arm64", "darwin", "arm64"),
    ("darwin-x64", "darwin", "x64"),
    ("linux-arm64", "linux", "arm64"),
    ("linux-x64", "linux", "x64"),
    ("win32-arm64", "win32", "arm64"),
    ("win32-x64", "win32", "x64"),
)
NATIVE_VARIANT = {"Linux": "linux-x64", "Windows": "win32-x64"}


class NoRegistryRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, new_url):
        raise ValueError("npm registry metadata redirected unexpectedly")


def stable_version(version):
    if not isinstance(version, str) or re.fullmatch(
            r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version) is None:
        raise ValueError("expected a stable numeric Codex version")


def aliases(version):
    stable_version(version)
    return [(PACKAGE, version, None, None)] + [
        (f"{PACKAGE}-{suffix}", f"{version}-{suffix}", system, cpu)
        for suffix, system, cpu in VARIANTS
    ]


def expected_optional_dependencies(version):
    return {alias: f"npm:{PACKAGE}@{package_version}"
            for alias, package_version, _, _ in aliases(version)[1:]}


def metadata_url(package_version):
    if not isinstance(package_version, str) or re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+(?:-(?:darwin|linux|win32)-(?:arm64|x64))?",
            package_version) is None:
        raise ValueError("invalid npm package version")
    return f"{REGISTRY}/@openai%2fcodex/{package_version}"


def tarball_url(package_version):
    metadata_url(package_version)
    return f"{REGISTRY}/@openai/codex/-/codex-{package_version}.tgz"


def strict_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON metadata key")
        value[key] = item
    return value


def fetch_metadata(package_version, open_url=None):
    url = metadata_url(package_version)
    open_url = open_url or urllib.request.build_opener(NoRegistryRedirect()).open
    request = urllib.request.Request(url, headers={
        "Accept": "application/json", "User-Agent": "codex-autoapprover-npm-candidate",
    })
    with open_url(request, timeout=30) as response:
        if response.geturl() != url:
            raise ValueError("unexpected npm registry metadata redirect")
        body = response.read(MAX_METADATA_BYTES + 1)
    if len(body) > MAX_METADATA_BYTES:
        raise ValueError("npm registry metadata exceeded limit")
    result = json.loads(body, object_pairs_hook=strict_json_object)
    if not isinstance(result, dict):
        raise ValueError("unexpected npm registry metadata response")
    return result


def valid_integrity(value):
    if not isinstance(value, str) or not value.startswith("sha512-"):
        return False
    encoded = value.removeprefix("sha512-")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        return False
    return len(raw) == 64 and base64.b64encode(raw).decode("ascii") == encoded


def package_record(metadata, alias, package_version, system, cpu, base_version):
    if (not isinstance(metadata, dict) or metadata.get("name") != PACKAGE
            or metadata.get("version") != package_version):
        raise ValueError("npm package name or version differs from the selected candidate")
    dist = metadata.get("dist")
    if (not isinstance(dist, dict) or dist.get("tarball") != tarball_url(package_version)
            or not valid_integrity(dist.get("integrity"))):
        raise ValueError("npm package tarball or integrity metadata is invalid")
    if metadata.get("dependencies") not in (None, {}):
        raise ValueError("candidate npm package introduced unreviewed dependencies")
    if system is None:
        if (metadata.get("optionalDependencies") != expected_optional_dependencies(base_version)
                or metadata.get("bin") != {"codex": "bin/codex.js"}):
            raise ValueError("Codex npm native-package aliases or launcher changed")
    else:
        if (metadata.get("os") != [system] or metadata.get("cpu") != [cpu]
                or metadata.get("optionalDependencies") not in (None, {})):
            raise ValueError("Codex npm native package platform or dependencies changed")
    return {"alias": alias, "version": package_version,
            "tarball": dist["tarball"], "integrity": dist["integrity"]}


def fetch_npm_records(version, open_url=None):
    return [package_record(fetch_metadata(package_version, open_url), alias,
                           package_version, system, cpu, version)
            for alias, package_version, system, cpu in aliases(version)]


def require_npm_records(candidate, version):
    stable_version(version)
    if not isinstance(candidate, dict) or candidate.get("codex_version") != version:
        raise ValueError("candidate version differs from npm package version")
    records = candidate.get("npm_packages")
    expected = aliases(version)
    if not isinstance(records, list) or len(records) != len(expected):
        raise ValueError("candidate has incomplete npm package metadata")
    for record, (alias, package_version, _, _) in zip(records, expected):
        if (not isinstance(record, dict)
                or set(record) != {"alias", "version", "tarball", "integrity"}
                or record["alias"] != alias or record["version"] != package_version
                or record["tarball"] != tarball_url(package_version)
                or not valid_integrity(record["integrity"])):
            raise ValueError("candidate npm package identity is invalid")
    return records


def verify_lock(lock, candidate, version, system):
    if system not in NATIVE_VARIANT:
        raise ValueError("npm candidate install requires native Linux or Windows")
    records = require_npm_records(candidate, version)
    if (not isinstance(lock, dict) or type(lock.get("lockfileVersion")) is not int
            or lock["lockfileVersion"] != 3 or not isinstance(lock.get("packages"), dict)):
        raise ValueError("expected npm lockfile version 3")
    packages = lock["packages"]
    expected_paths = {""} | {f"node_modules/{item['alias']}" for item in records}
    if set(packages) != expected_paths or not isinstance(packages[""], dict):
        raise ValueError("npm lockfile has missing or unexpected packages")
    if packages[""].get("dependencies") != {PACKAGE: version}:
        raise ValueError("npm lockfile root does not pin the exact Codex version")
    expected_optional = expected_optional_dependencies(version)
    for record, (alias, _, os_name, cpu) in zip(records, aliases(version)):
        entry = packages[f"node_modules/{alias}"]
        if (not isinstance(entry, dict) or entry.get("version") != record["version"]
                or entry.get("resolved") != record["tarball"]
                or entry.get("integrity") != record["integrity"]
                or entry.get("dependencies") not in (None, {})):
            raise ValueError("npm lockfile differs from recorded package integrity")
        if os_name is None:
            if (entry.get("optionalDependencies") != expected_optional
                    or entry.get("bin") != {"codex": "bin/codex.js"}
                    or entry.get("optional") is True):
                raise ValueError("npm lockfile parent dependencies changed")
        elif (entry.get("name") != PACKAGE or entry.get("os") != [os_name]
              or entry.get("cpu") != [cpu] or entry.get("optional") is not True):
            raise ValueError("npm lockfile native package identity changed")
    return next(item for item in records
                if item["alias"] == f"{PACKAGE}-{NATIVE_VARIANT[system]}")


def verify_installed(install_root: Path, version: str, system: str):
    if system not in NATIVE_VARIANT:
        raise ValueError("npm candidate install requires native Linux or Windows")
    package_root = install_root / "node_modules" / "@openai"
    native_name = f"codex-{NATIVE_VARIANT[system]}"
    if (package_root.is_symlink() or not package_root.is_dir()
            or {item.name for item in package_root.iterdir()} != {"codex", native_name}):
        raise ValueError("installed npm package set differs from the candidate lock")
    for folder, expected_version in (("codex", version), (native_name, f"{version}-{NATIVE_VARIANT[system]}")):
        path = package_root / folder
        manifest = path / "package.json"
        if (path.is_symlink() or not path.is_dir() or manifest.is_symlink()
                or not manifest.is_file()):
            raise ValueError("installed npm package path is unsafe")
        package = json.loads(manifest.read_bytes(), object_pairs_hook=strict_json_object)
        if package.get("name") != PACKAGE or package.get("version") != expected_version:
            raise ValueError("installed npm package identity differs from its lock")
        if folder == "codex" and package.get("bin") != {"codex": "bin/codex.js"}:
            raise ValueError("installed npm launcher differs from its lock")
