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

from npm_candidate import fetch_npm_records, strict_json_object

VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
UPSTREAM = "https://api.github.com/repos/openai/codex/releases"
LATEST = f"{UPSTREAM}/latest"
GIT_API = "https://api.github.com/repos/openai/codex/git"
LIMIT = 4 * 1024 * 1024
GIT_LIMIT = 128 * 1024
TAG_REF_LIMIT = 2 * 1024 * 1024
MAX_TAG_REFS = 5000
MAX_UNLISTED_TAG_LOOKUPS = 16
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


def exact_json_equal(left, right):
    return (json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False)
            == json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False))


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
    release = json.loads(body, object_pairs_hook=strict_json_object)
    if not isinstance(release, dict):
        raise ValueError("latest release API returned an unexpected response")
    return release


def fetch_tagged_record(version, open_url=None):
    """Fetch one exact release tag, including an unpublished draft if visible."""
    version_key(version)
    tag = f"rust-v{version}"
    url = f"{UPSTREAM}/tags/{tag}"
    open_url = open_url or urllib.request.build_opener(NoApiRedirect()).open
    request = urllib.request.Request(url, headers=api_headers())
    with open_url(request, timeout=30) as response:
        if response.geturl() != request.full_url:
            raise ValueError("unexpected tagged release API redirect")
        body = response.read(LIMIT + 1)
    if len(body) > LIMIT:
        raise ValueError("tagged release API response exceeded limit")
    release = json.loads(body, object_pairs_hook=strict_json_object)
    if not isinstance(release, dict) or release.get("tag_name") != tag:
        raise ValueError("tagged release API returned an unexpected response")
    return release


def fetch_tagged_release(version, open_url=None):
    """Refresh one complete stable candidate by its exact official release tag."""
    release = fetch_tagged_record(version, open_url)
    candidate_from_releases([release])
    return release


def fetch_upstream_source(version, open_url=None):
    """Bind a release tag ref and its peeled source commit through the Git API."""
    version_key(version)
    tag = f"rust-v{version}"
    open_url = open_url or urllib.request.build_opener(NoApiRedirect()).open

    def read(url):
        request = urllib.request.Request(url, headers=api_headers())
        with open_url(request, timeout=30) as response:
            if response.geturl() != request.full_url:
                raise ValueError("upstream Git API redirected unexpectedly")
            body = response.read(GIT_LIMIT + 1)
        if len(body) > GIT_LIMIT:
            raise ValueError("upstream Git API response exceeded limit")
        record = json.loads(body, object_pairs_hook=strict_json_object)
        if not isinstance(record, dict):
            raise ValueError("invalid upstream Git API record")
        return record

    ref = read(f"{GIT_API}/ref/tags/{tag}")
    pointer = ref.get("object")
    if ref.get("ref") != f"refs/tags/{tag}" or not isinstance(pointer, dict):
        raise ValueError("upstream release tag reference is invalid")
    kind = pointer.get("type")
    oid = pointer.get("sha")
    if kind not in {"commit", "tag"} or not isinstance(oid, str) or not GIT_SHA.fullmatch(oid):
        raise ValueError("upstream release tag object is invalid")
    expected_url = f"{GIT_API}/{'tags' if kind == 'tag' else 'commits'}/{oid}"
    if pointer.get("url") != expected_url:
        raise ValueError("upstream release tag object URL is invalid")
    commit = oid
    if kind == "tag":
        annotation = read(f"{GIT_API}/tags/{oid}")
        target = annotation.get("object")
        if (annotation.get("sha") != oid or annotation.get("tag") != tag
                or not isinstance(target, dict) or target.get("type") != "commit"
                or not isinstance(target.get("sha"), str)
                or not GIT_SHA.fullmatch(target["sha"])
                or target.get("url") != f"{GIT_API}/commits/{target['sha']}"):
            raise ValueError("upstream annotated release tag is invalid")
        commit = target["sha"]
    return {"upstream_tag_ref_sha": oid, "upstream_source_sha": commit}


def fetch_stable_tag_versions(open_url=None):
    """List all stable numeric Rust tag refs as a backstop for release ordering."""
    open_url = open_url or urllib.request.build_opener(NoApiRedirect()).open
    url = f"{GIT_API}/matching-refs/tags/rust-v"
    request = urllib.request.Request(url, headers=api_headers())
    with open_url(request, timeout=30) as response:
        if response.geturl() != request.full_url:
            raise ValueError("upstream tag-ref API redirected unexpectedly")
        body = response.read(TAG_REF_LIMIT + 1)
    if len(body) > TAG_REF_LIMIT:
        raise ValueError("upstream tag-ref API response exceeded limit")
    records = json.loads(body, object_pairs_hook=strict_json_object)
    if not isinstance(records, list) or len(records) > MAX_TAG_REFS:
        raise ValueError("upstream tag-ref listing is invalid or too large")
    versions, refs = set(), set()
    for record in records:
        ref = record.get("ref") if isinstance(record, dict) else None
        if not isinstance(ref, str) or not ref.startswith("refs/tags/rust-v") or ref in refs:
            raise ValueError("upstream tag-ref listing is ambiguous")
        refs.add(ref)
        version = ref.removeprefix("refs/tags/rust-v")
        if VERSION.fullmatch(version):
            versions.add(version)
    return versions


def complete_release_window(recent, previous_version):
    """Recover published numeric tags that sorted behind the recorded baseline."""
    version_key(previous_version)
    tags = fetch_stable_tag_versions()
    if previous_version not in tags:
        raise ValueError("previous release tag missing from official refs; manual recovery required")
    listed = {item["tag_name"].removeprefix("rust-v") for item in recent
              if isinstance(item, dict) and isinstance(item.get("tag_name"), str)
              and item["tag_name"].startswith("rust-v")
              and VERSION.fullmatch(item["tag_name"].removeprefix("rust-v"))
              and item.get("draft") is False and item.get("prerelease") is False}
    missing = sorted((version for version in tags
                      if version_key(version) > version_key(previous_version)
                      and version not in listed), key=version_key)
    if len(missing) > MAX_UNLISTED_TAG_LOOKUPS:
        raise ValueError("too many unlisted stable tags; manual recovery required")
    complete = list(recent)
    for version in missing:
        try:
            record = fetch_tagged_record(version)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                continue  # A Git tag alone is not a published release.
            raise
        if record.get("draft") is True or record.get("prerelease") is True:
            continue
        candidate_from_releases([record])
        complete.append(record)
    return complete


def bind_upstream_source(candidate, identity):
    if (not isinstance(identity, dict) or set(identity) != {"upstream_tag_ref_sha", "upstream_source_sha"}
            or any(not isinstance(value, str) or not GIT_SHA.fullmatch(value)
                   for value in identity.values())):
        raise ValueError("invalid upstream source identity")
    bound = dict(candidate)
    bound["schema_version"] = 3
    bound.update(identity)
    return bound


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
        batch = json.loads(body, object_pairs_hook=strict_json_object)
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


def verified_release_backlog(previous, candidate, recent, current_source):
    """Verify the baseline and return every newer stable candidate, oldest first."""
    old_version = previous["codex_version"]
    version_key(old_version)
    old_tag = f"rust-v{old_version}"
    if previous.get("upstream_tag") != old_tag:
        raise ValueError("previous candidate tag/version mismatch")
    prior_id = previous.get("upstream_release_id")
    if prior_id is not None and (type(prior_id) is not int or prior_id <= 0):
        raise ValueError("previous release identity is invalid")
    old = [item for item in recent if isinstance(item, dict) and item.get("tag_name") == old_tag]
    if len(old) != 1 or (prior_id is not None and old[0].get("id") != prior_id):
        raise ValueError("previous release identity changed or became ambiguous")
    recorded_old = candidate_from_releases(old)
    if type(previous.get("schema_version")) is not int or previous["schema_version"] != 3:
        raise ValueError("previous candidate lacks a pinned upstream source; manual recovery required")
    if not exact_json_equal(
            {key: value for key, value in previous.items() if key != "npm_packages"},
            bind_upstream_source(recorded_old, current_source)):
        raise ValueError("previous release asset, source or candidate metadata changed")
    # The /latest pointer is based on commit creation time, so it need not be
    # the greatest numeric version. Require its exact identity in the listing.
    stable = {}
    for item in recent:
        if not isinstance(item, dict):
            raise ValueError("invalid release record")
        if item.get("draft") is not False or item.get("prerelease") is not False:
            continue
        tag = item.get("tag_name")
        if isinstance(tag, str) and tag.startswith("rust-v") and VERSION.fullmatch(tag[6:]):
            record = candidate_from_releases([item])
            version = record["codex_version"]
            if version in stable and not exact_json_equal(stable[version], record):
                raise ValueError("conflicting duplicate stable release metadata")
            stable[version] = record
    if candidate["codex_version"] not in stable or not exact_json_equal(
            stable[candidate["codex_version"]], candidate):
        raise ValueError("latest release and recent release listing disagree")
    return [stable[version] for version in sorted(stable, key=version_key)
            if version_key(version) > version_key(old_version)]


def write_candidate(path, candidate):
    """Idempotent, refuse downgrades and unexpected same-version release replacement."""
    if path.exists():
        previous = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_json_object)
        old = version_key(previous["codex_version"])
        new = version_key(candidate["codex_version"])
        if old > new:
            raise ValueError("upstream is older than the recorded candidate; refusing downgrade")
        if old == new:
            if exact_json_equal(previous, candidate):
                return False
            legacy = {key: value for key, value in candidate.items()
                      if key not in {"assets", "npm_packages"}}
            legacy["schema_version"] = 1
            previous_id = previous.get("upstream_release_id")
            if previous_id is not None and (type(previous_id) is not int or previous_id <= 0):
                raise ValueError("same-version upstream release id is invalid")
            if previous_id not in (None, candidate["upstream_release_id"]):
                raise ValueError("same-version upstream release id changed")
            legacy["upstream_release_id"] = previous_id
            if (type(previous.get("schema_version")) is not int
                    or previous["schema_version"] != 1
                    or not exact_json_equal(previous, legacy)):
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


def repository_name():
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    return repository


def verify_open_candidate_pr(candidate, pr_sha):
    """An open PR must still pin the current official release and npm identities."""
    version = candidate["codex_version"]
    if not isinstance(pr_sha, str) or re.fullmatch(r"[0-9a-f]{40}", pr_sha) is None:
        raise ValueError("open candidate PR has an invalid head commit")
    tagged = candidate_from_releases([fetch_tagged_release(version)])
    if not exact_json_equal(tagged, candidate):
        raise ValueError("open candidate PR release listing and tag disagree")
    expected = bind_upstream_source(candidate, fetch_upstream_source(version))
    expected["npm_packages"] = fetch_npm_records(version)
    branch = f"refs/heads/automation/codex-{version}"
    subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin", branch], check=True)
    fetched = subprocess.check_output(["git", "rev-parse", "FETCH_HEAD"], text=True).strip()
    if fetched != pr_sha:
        raise ValueError("open candidate PR branch moved during verification")
    size = subprocess.check_output(
        ["git", "cat-file", "-s", "FETCH_HEAD:compatibility/candidate.json"], text=True).strip()
    if not size.isdecimal() or int(size) > 128 * 1024:
        raise ValueError("open candidate PR metadata exceeds limit")
    recorded = json.loads(subprocess.check_output(
        ["git", "show", "FETCH_HEAD:compatibility/candidate.json"], text=True),
        object_pairs_hook=strict_json_object)
    if not exact_json_equal(recorded, expected):
        raise ValueError("open candidate PR metadata differs from official release; manual recovery required")


def candidate_pr_exists(version, expected=None):
    """Treat an earlier same-repository PR, including a closed one, as a decision."""
    version_key(version)
    if expected is not None and expected.get("codex_version") != version:
        raise ValueError("candidate PR version mismatch")
    repository = repository_name()
    branch = f"automation/codex-{version}"
    existing = subprocess.check_output([
        "gh", "pr", "list", "--repo", repository, "--head", branch,
        "--state", "all", "--json", "number,headRefName,headRepositoryOwner,isCrossRepository,state,headRefOid",
        "--limit", "100",
    ], text=True)
    records = json.loads(existing, object_pairs_hook=strict_json_object)
    if not isinstance(records, list) or len(records) == 100:
        raise ValueError("candidate PR history is ambiguous; manual recovery required")
    found = False
    for record in records:
        if not isinstance(record, dict) or type(record.get("number")) is not int or record["number"] <= 0:
            raise ValueError("invalid candidate PR metadata")
        owner = record.get("headRepositoryOwner")
        if (record.get("headRefName") != branch or not isinstance(owner, dict)
                or not isinstance(owner.get("login"), str)
                or type(record.get("isCrossRepository")) is not bool
                or record.get("state") not in {"OPEN", "CLOSED", "MERGED"}):
            raise ValueError("candidate PR head identity is ambiguous; manual recovery required")
        if (not record["isCrossRepository"]
                and owner["login"].casefold() == repository.split("/", 1)[0].casefold()):
            found = True
            if expected is not None and record["state"] == "OPEN":
                verify_open_candidate_pr(expected, record.get("headRefOid"))
    return found


def prepare_pr(candidate, path):
    repository = repository_name()
    version = candidate["codex_version"]
    version_key(version)
    branch = f"automation/codex-{version}"
    # Closed PRs are retained as decisions. Do not reopen/overwrite a maintainer's work.
    if candidate_pr_exists(version):
        print(f"Candidate PR already exists for Codex {version}; left unchanged")
        return False
    remote = subprocess.check_output(["git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}"], text=True)
    if remote.strip():
        subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin",
                        f"refs/heads/{branch}"], check=True)
        existing_candidate = subprocess.check_output(
            ["git", "show", "FETCH_HEAD:compatibility/candidate.json"], text=True)
        if not exact_json_equal(
                json.loads(existing_candidate, object_pairs_hook=strict_json_object), candidate):
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
    return True


def candidate_branch_sha(version):
    version_key(version)
    ref = f"refs/heads/automation/codex-{version}"
    output = subprocess.check_output(
        ["git", "ls-remote", "--exit-code", "--heads", "origin", ref],
        text=True, timeout=30)
    lines = output.splitlines()
    if len(lines) != 1:
        raise ValueError("candidate branch has no unique remote commit")
    sha, separator, returned_ref = lines[0].partition("\t")
    if separator != "\t" or returned_ref != ref or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        raise ValueError("candidate branch remote identity is invalid")
    return sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, help="Read a local API fixture instead of using the network")
    parser.add_argument("--output", type=Path, default=Path("compatibility/candidate.json"))
    parser.add_argument("--create-pr", action="store_true")
    parser.add_argument("--version", help="Refresh one exact official candidate version")
    parser.add_argument("--require-branch", action="store_true",
                        help="Require an existing candidate branch for an explicit repair retry")
    args = parser.parse_args()
    if args.fixture and args.create_pr:
        parser.error("fixtures cannot create PRs")
    if args.fixture and args.version:
        parser.error("fixtures cannot select an official version")
    if args.require_branch and not args.create_pr:
        parser.error("--require-branch requires --create-pr")
    if args.require_branch and not args.version:
        parser.error("--require-branch requires --version")
    if args.create_pr and args.version and not args.require_branch:
        parser.error("--version with --create-pr requires --require-branch")
    if args.create_pr and not args.require_branch and not args.output.exists():
        raise ValueError("baseline candidate missing; manual recovery required")

    candidate = None
    prior_npm = None
    prior_source = None
    if args.fixture:
        candidate = candidate_from_releases(
            json.loads(args.fixture.read_text(), object_pairs_hook=strict_json_object))
    elif args.version:
        candidate = candidate_from_releases([fetch_tagged_release(args.version)])
    elif args.output.exists():
        previous = json.loads(args.output.read_text(encoding="utf-8"),
                              object_pairs_hook=strict_json_object)
        latest = candidate_from_releases([fetch_latest_release()])
        recent = complete_release_window(
            fetch_releases(stop_tag=previous.get("upstream_tag")), previous["codex_version"])
        prior_source = fetch_upstream_source(previous["codex_version"])
        backlog = verified_release_backlog(previous, latest, recent, prior_source)
        prior_npm = fetch_npm_records(previous["codex_version"])
        if not exact_json_equal(previous.get("npm_packages"), prior_npm):
            raise ValueError("previous npm package identity changed; manual investigation required")
        if args.create_pr:
            for entry in backlog:
                exists = candidate_pr_exists(entry["codex_version"], expected=entry)
                if not exists and candidate is None:
                    candidate = entry
        else:
            candidate = backlog[0] if backlog else candidate_from_releases(
                [item for item in recent if isinstance(item, dict)
                 and item.get("tag_name") == previous["upstream_tag"]])
    else:
        candidate = candidate_from_releases([fetch_latest_release()])

    if candidate is not None and not args.fixture:
        source = (prior_source if prior_source is not None
                  and candidate["codex_version"] == previous["codex_version"]
                  else fetch_upstream_source(candidate["codex_version"]))
        candidate = bind_upstream_source(candidate, source)

    if candidate is None:
        # Every newer version already has a candidate PR or a recorded decision.
        version = latest["codex_version"]
        changed = False
        created_pr = False
        branch_sha = None
    elif args.require_branch:
        candidate["npm_packages"] = fetch_npm_records(candidate["codex_version"])
        version = candidate["codex_version"]
        changed = False
        created_pr = False
        branch_sha = candidate_branch_sha(version)
    else:
        if not args.fixture:
            candidate["npm_packages"] = (prior_npm if prior_npm is not None
                                         and candidate["codex_version"] == previous["codex_version"]
                                         else fetch_npm_records(candidate["codex_version"]))
        version = candidate["codex_version"]
        changed = write_candidate(args.output, candidate)
        created_pr = prepare_pr(candidate, args.output) is True if changed and args.create_pr else False
        if args.create_pr:
            changed = created_pr
        branch_sha = candidate_branch_sha(version) if created_pr else None
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as output:
            output.write(f"version={version}\nchanged={str(changed).lower()}\n"
                         f"repair_eligible={str(created_pr).lower()}\n")
            if branch_sha:
                output.write(f"candidate_sha={branch_sha}\n")
    print(f"Codex {version}: unverified; candidate changed={changed}")


if __name__ == "__main__":
    main()
