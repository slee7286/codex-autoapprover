#!/usr/bin/env python3
"""Detect upstream releases and prepare an unverified candidate. Never approve support.

Only fixed official API URLs are fetched. Release text is not interpreted as code
or instructions. Network errors fail the run and leave the candidate untouched.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.request

VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
UPSTREAM = "https://api.github.com/repos/openai/codex/releases"
LATEST = f"{UPSTREAM}/latest"
LIMIT = 4 * 1024 * 1024
# Five asset-heavy releases fit the per-response cap observed in the live API.
PAGE_SIZE = 5
MAX_PAGES = 20
REQUIRED_ASSETS = (
    "codex-x86_64-unknown-linux-musl.tar.gz",
    "codex-x86_64-pc-windows-msvc.exe",
)


class NoApiRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("release API redirected unexpectedly")


def api_headers():
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "codex-autoapprover-release-watch"}
    token = os.environ.get("GH_TOKEN")
    if token:
        if "\n" in token or "\r" in token:
            raise ValueError("invalid GitHub API token format")
        headers["Authorization"] = f"Bearer {token}"
    return headers


def version_key(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ValueError("expected a stable numeric Codex version")
    return tuple(map(int, value.split(".")))


def required_assets(release, tag):
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValueError("stable release is missing asset metadata")
    selected = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise ValueError("invalid release asset record")
        name = asset.get("name")
        if name not in REQUIRED_ASSETS:
            continue
        if name in selected:
            raise ValueError("duplicate required release asset")
        expected_url = f"https://github.com/openai/codex/releases/download/{tag}/{name}"
        if (type(asset.get("id")) is not int or asset["id"] <= 0
                or type(asset.get("size")) is not int or not 0 < asset["size"] <= 2 * 1024**3
                or not isinstance(asset.get("digest"), str) or not DIGEST.fullmatch(asset["digest"])
                or asset.get("browser_download_url") != expected_url):
            raise ValueError("required release asset has invalid identity metadata")
        selected[name] = {
            "name": name,
            "id": asset["id"],
            "size": asset["size"],
            "digest": asset["digest"],
            "url": expected_url,
        }
    if set(selected) != set(REQUIRED_ASSETS):
        raise ValueError("stable release is missing a required native asset")
    return [selected[name] for name in REQUIRED_ASSETS]


def candidate_from_releases(releases):
    if not isinstance(releases, list):
        raise ValueError("release API returned an unexpected response")
    candidates = []
    seen = {}
    for release in releases:
        if not isinstance(release, dict):
            raise ValueError("invalid release record")
        if release.get("draft") is not False or release.get("prerelease") is not False:
            continue
        tag = release.get("tag_name", "")
        if not isinstance(tag, str) or not tag.startswith("rust-v"):
            continue
        version = tag.removeprefix("rust-v")
        if not VERSION.fullmatch(version):
            continue
        if type(release.get("id")) is not int or release["id"] <= 0:
            raise ValueError("invalid release id")
        identity = (release["id"], release.get("assets"))
        if version in seen:
            if seen[version] != identity:
                raise ValueError("conflicting duplicate stable release metadata")
            continue
        seen[version] = identity
        candidates.append(release)
    if not candidates:
        raise ValueError("no stable Codex release in the bounded API window")
    selected = max(candidates, key=lambda item: version_key(item["tag_name"].removeprefix("rust-v")))
    tag = selected["tag_name"]
    version = tag.removeprefix("rust-v")
    return {
        "schema_version": 2,
        "codex_version": version,
        "upstream_release_id": selected["id"],
        "upstream_tag": tag,
        "upstream_url": f"https://github.com/openai/codex/releases/tag/{tag}",
        "assets": required_assets(selected, tag),
        "status": "unverified",
        "required_platforms": ["linux-x86_64", "windows-x86_64"],
    }


def fetch_latest_release(open_url=None):
    """Use GitHub's latest full-release pointer instead of crawling all history."""
    open_url = open_url or urllib.request.build_opener(NoApiRedirect()).open
    request = urllib.request.Request(LATEST, headers=api_headers())
    with open_url(request, timeout=30) as response:
        if response.geturl() != request.full_url:
            raise ValueError("unexpected latest release API redirect")
        body = response.read(LIMIT + 1)
    if len(body) > LIMIT:
        raise ValueError("latest release API response exceeded limit")
    release = json.loads(body)
    if not isinstance(release, dict):
        raise ValueError("latest release API returned an unexpected response")
    return release


def fetch_releases(open_url=None, stop_tag=None):
    """Audit a bounded window or stop at the previously recorded stable tag."""
    if stop_tag is not None:
        if not isinstance(stop_tag, str) or not stop_tag.startswith("rust-v"):
            raise ValueError("invalid previous release tag")
        version_key(stop_tag.removeprefix("rust-v"))
    releases = []
    open_url = open_url or urllib.request.build_opener(NoApiRedirect()).open
    # Bounded pagination accommodates bursts of prereleases without an unbounded crawl.
    for page in range(1, MAX_PAGES + 1):
        request = urllib.request.Request(
            f"{UPSTREAM}?per_page={PAGE_SIZE}&page={page}",
            headers=api_headers(),
        )
        with open_url(request, timeout=30) as response:
            if response.geturl() != request.full_url:
                raise ValueError("unexpected release API redirect")
            body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise ValueError("release API response exceeded limit")
        batch = json.loads(body)
        if not isinstance(batch, list):
            raise ValueError("invalid release page")
        releases.extend(batch)
        if stop_tag is not None and any(isinstance(item, dict) and item.get("tag_name") == stop_tag
                                    for item in batch):
            return releases
        if len(batch) < PAGE_SIZE:
            if stop_tag is not None:
                raise ValueError("previous release absent from bounded API window; manual recovery required")
            return releases
    raise ValueError("release API pagination limit reached; refusing a truncated candidate window")


def verify_release_gap(previous, candidate, recent):
    """Do not silently skip stable releases that appeared since the last poll."""
    old_version = previous["codex_version"]
    version_key(old_version)
    old_tag = f"rust-v{old_version}"
    if previous.get("upstream_tag") != old_tag:
        raise ValueError("previous candidate tag/version mismatch")
    old = [item for item in recent if isinstance(item, dict) and item.get("tag_name") == old_tag]
    if len(old) != 1 or (previous.get("upstream_release_id") is not None
                         and old[0].get("id") != previous["upstream_release_id"]):
        raise ValueError("previous release identity changed or became ambiguous")
    selected = candidate_from_releases(recent)
    if selected != candidate:
        raise ValueError("latest release and recent release listing disagree")
    newer = set()
    for item in recent:
        if not isinstance(item, dict):
            raise ValueError("invalid release record")
        if item.get("draft") is not False or item.get("prerelease") is not False:
            continue
        tag = item.get("tag_name")
        if isinstance(tag, str) and tag.startswith("rust-v") and VERSION.fullmatch(tag[6:]):
            if version_key(tag[6:]) > version_key(old_version):
                newer.add(tag)
    if newer != {candidate["upstream_tag"]}:
        raise ValueError("multiple or inconsistent new stable releases; manual recovery required")


def write_candidate(path, candidate):
    """Idempotent, refuse downgrades and unexpected same-version release replacement."""
    if path.exists():
        previous = json.loads(path.read_text(encoding="utf-8"))
        old = version_key(previous["codex_version"])
        new = version_key(candidate["codex_version"])
        if old > new:
            raise ValueError("upstream is older than the recorded candidate; refusing downgrade")
        if old == new:
            if previous == candidate:
                return False
            legacy = {key: value for key, value in candidate.items() if key != "assets"}
            legacy["schema_version"] = 1
            previous_id = previous.get("upstream_release_id")
            if previous_id not in (None, candidate["upstream_release_id"]):
                raise ValueError("same-version upstream release id changed")
            legacy["upstream_release_id"] = previous_id
            if previous.get("schema_version") != 1 or previous != legacy:
                raise ValueError("same-version upstream metadata changed; manual investigation required")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as output:
        staged = Path(output.name)
        json.dump(candidate, output, indent=2)
        output.write("\n")
    try:
        os.replace(staged, path)
    finally:
        staged.unlink(missing_ok=True)
    return True


def prepare_pr(candidate, path):
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    version = candidate["codex_version"]
    version_key(version)
    branch = f"automation/codex-{version}"
    # Closed PRs are retained as decisions. Do not reopen/overwrite a maintainer's work.
    existing = subprocess.check_output([
        "gh", "pr", "list", "--repo", repository, "--head", branch,
        "--state", "all", "--json", "number", "--limit", "1",
    ], text=True)
    if json.loads(existing):
        print(f"Candidate PR already exists for Codex {version}; left unchanged")
        return
    remote = subprocess.check_output(["git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}"], text=True)
    if remote.strip():
        subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin",
                        f"refs/heads/{branch}"], check=True)
        existing_candidate = subprocess.check_output(
            ["git", "show", "FETCH_HEAD:compatibility/candidate.json"], text=True)
        if json.loads(existing_candidate) != candidate:
            raise ValueError("candidate branch differs from official release metadata; manual recovery required")
        changed_paths = subprocess.check_output(
            ["git", "diff", "--name-only", "HEAD", "FETCH_HEAD"], text=True).splitlines()
        if changed_paths != ["compatibility/candidate.json"]:
            raise ValueError("candidate branch contains unexpected changes; manual recovery required")
    else:
        subprocess.run(["git", "switch", "-c", branch], check=True)
        subprocess.run(["git", "add", "--", str(path)], check=True)
        subprocess.run(["git", "-c", "user.name=codex-compatibility-bot", "-c",
                        "user.email=codex-compatibility-bot@users.noreply.github.com",
                        "commit", "-m", f"Track unverified Codex {version}"], check=True)
        subprocess.run(["git", "push", "--", "origin", branch], check=True)
    body = (
        f"Detected official Codex {version}: {candidate['upstream_url']}.\n\n"
        "This changes candidate metadata only. Automatic approvals stay disabled for this version.\n\n"
        "Required: inspect upstream protocol/sandbox changes, repair the adapter if needed, run the "
        "native validation matrix, retain redacted live evidence, and complete independent review. "
        "Follow docs/production-plan.md and docs/production-goal.md. "
        "A passing help probe or synthetic suite is not compatibility certification.\n\n"
        "The watcher runs candidate checks in its own workflow because PR checks created with GITHUB_TOKEN "
        "may require explicit workflow approval. Re-run full PR checks after reviewed code changes.\n"
    )
    with tempfile.TemporaryDirectory() as directory:
        body_path = Path(directory) / "body.md"
        body_path.write_text(body, encoding="utf-8")
        subprocess.run(["gh", "pr", "create", "--repo", repository, "--head", branch,
                        "--draft", "--title", f"Validate Codex {version} compatibility",
                        "--body-file", str(body_path)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, help="Read a local API fixture instead of using the network")
    parser.add_argument("--output", type=Path, default=Path("compatibility/candidate.json"))
    parser.add_argument("--create-pr", action="store_true")
    args = parser.parse_args()
    if args.fixture and args.create_pr:
        parser.error("fixtures cannot create PRs")
    releases = json.loads(args.fixture.read_text()) if args.fixture else [fetch_latest_release()]
    candidate = candidate_from_releases(releases)
    if not args.fixture and args.output.exists():
        previous = json.loads(args.output.read_text(encoding="utf-8"))
        if version_key(candidate["codex_version"]) > version_key(previous["codex_version"]):
            old_tag = previous.get("upstream_tag")
            recent = fetch_releases(stop_tag=old_tag)
            verify_release_gap(previous, candidate, recent)
    changed = write_candidate(args.output, candidate)
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as output:
            output.write(f"version={candidate['codex_version']}\nchanged={str(changed).lower()}\n")
    print(f"Codex {candidate['codex_version']}: unverified; candidate changed={changed}")
    if changed and args.create_pr:
        prepare_pr(candidate, args.output)


if __name__ == "__main__":
    main()
