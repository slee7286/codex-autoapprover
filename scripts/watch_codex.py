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
UPSTREAM = "https://api.github.com/repos/openai/codex/releases"
LIMIT = 4 * 1024 * 1024


def version_key(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ValueError("expected a stable numeric Codex version")
    return tuple(map(int, value.split(".")))


def candidate_from_releases(releases):
    if not isinstance(releases, list):
        raise ValueError("release API returned an unexpected response")
    candidates = []
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
        candidates.append({
            "schema_version": 1,
            "codex_version": version,
            "upstream_release_id": release["id"],
            "upstream_tag": tag,
            "upstream_url": f"https://github.com/openai/codex/releases/tag/{tag}",
            "status": "unverified",
            "required_platforms": ["linux-x86_64", "windows-x86_64"],
        })
    if not candidates:
        raise ValueError("no stable Codex release in the bounded API window")
    return max(candidates, key=lambda item: version_key(item["codex_version"]))


def fetch_releases():
    releases = []
    # Bounded pagination accommodates bursts of prereleases without an unbounded crawl.
    for page in range(1, 21):
        request = urllib.request.Request(
            f"{UPSTREAM}?per_page=5&page={page}",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "codex-autoapprover-release-watch"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.geturl() != request.full_url:
                raise ValueError("unexpected release API redirect")
            body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise ValueError("release API response exceeded limit")
        batch = json.loads(body)
        if not isinstance(batch, list):
            raise ValueError("invalid release page")
        releases.extend(batch)
        if len(batch) < 5:
            break
    return releases


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
            hydrated = {**previous, "upstream_release_id": candidate["upstream_release_id"]}
            if previous.get("upstream_release_id") is not None or hydrated != candidate:
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
    if not remote.strip():
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
    releases = json.loads(args.fixture.read_text()) if args.fixture else fetch_releases()
    candidate = candidate_from_releases(releases)
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
