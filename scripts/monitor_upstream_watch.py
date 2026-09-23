#!/usr/bin/env python3
"""Read-only external heartbeat check for the scheduled Codex release watcher.

Run this outside GitHub Actions. A nonzero exit must be delivered to an alerting
system; a second GitHub schedule would share the failure mode being monitored.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


WORKFLOW_FILE = "upstream-watch.yml"
WORKFLOW_PATH = f".github/workflows/{WORKFLOW_FILE}"
SUCCESS_MAX_AGE = timedelta(hours=8)  # Six-hour cron plus a two-hour delay allowance.
ACTIVE_MAX_AGE = timedelta(hours=2)
FUTURE_SKEW = timedelta(minutes=5)
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_RUNS = 20
REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class MonitorAlert(Exception):
    """The watcher is inactive, late or failing; external alerting should fire."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("GitHub API redirected unexpectedly")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("GitHub API returned duplicate JSON fields")
        result[key] = value
    return result


def reject_nonfinite(value):
    raise ValueError(f"non-finite GitHub JSON value: {value}")


def fetch_json(url, open_url=None):
    if not url.startswith("https://api.github.com/repos/"):
        raise ValueError("monitor may fetch only the GitHub repository API")
    token = os.environ.get("GH_TOKEN")
    if token and ("\r" in token or "\n" in token):
        raise ValueError("invalid GitHub token format")
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "codex-autoapprover-external-watch-monitor"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    open_url = open_url or urllib.request.build_opener(NoRedirect()).open
    with open_url(request, timeout=20) as response:
        if response.geturl() != url or response.status != 200:
            raise ValueError("GitHub API returned an unexpected response")
        body = response.read(MAX_BODY_BYTES + 1)
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("GitHub API response exceeded monitor limit")
    return json.loads(body, object_pairs_hook=unique_object,
                      parse_constant=reject_nonfinite)


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError("workflow run lacks a creation timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("workflow run has an invalid creation timestamp") from error
    if result.tzinfo is None:
        raise ValueError("workflow run timestamp has no timezone")
    return result.astimezone(timezone.utc)


def inspect(repo, fetcher=fetch_json, now=None):
    if (not isinstance(repo, str) or not REPO_RE.fullmatch(repo)
            or any(part in {".", ".."} for part in repo.split("/"))):
        raise ValueError("repository must be OWNER/REPO")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("monitor clock must have a timezone")
    now = now.astimezone(timezone.utc)
    base = f"https://api.github.com/repos/{repo}"
    repository = fetcher(base)
    if (not isinstance(repository, dict)
            or not isinstance(repository.get("full_name"), str)
            or repository["full_name"].casefold() != repo.casefold()
            or not isinstance(repository.get("default_branch"), str)
            or not repository["default_branch"]
            or any(ord(char) < 33 for char in repository["default_branch"])):
        raise ValueError("GitHub repository identity or default branch is invalid")
    if repository.get("archived") is not False or repository.get("disabled") is not False:
        raise MonitorAlert("repository is archived or disabled")
    branch = repository["default_branch"]

    try:
        workflow = fetcher(f"{base}/actions/workflows/{WORKFLOW_FILE}")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            error.close()
            raise MonitorAlert(f"{WORKFLOW_FILE} is absent from the default branch or inaccessible") from error
        raise
    if (not isinstance(workflow, dict) or type(workflow.get("id")) is not int
            or workflow["id"] <= 0 or workflow.get("path") != WORKFLOW_PATH):
        raise ValueError("GitHub returned the wrong workflow identity")
    if workflow.get("state") != "active":
        raise MonitorAlert(f"{WORKFLOW_FILE} is not active")

    query = urllib.parse.urlencode({"branch": branch, "event": "schedule",
                                    "per_page": MAX_RUNS, "page": 1})
    listing = fetcher(f"{base}/actions/workflows/{WORKFLOW_FILE}/runs?{query}")
    if (not isinstance(listing, dict) or type(listing.get("total_count")) is not int
            or listing["total_count"] < 0 or not isinstance(listing.get("workflow_runs"), list)
            or len(listing["workflow_runs"]) > MAX_RUNS
            or listing["total_count"] < len(listing["workflow_runs"])):
        raise ValueError("GitHub returned an invalid workflow-run listing")
    if not listing["workflow_runs"]:
        raise MonitorAlert("no scheduled watcher run exists on the default branch")

    runs = []
    ids = set()
    for run in listing["workflow_runs"]:
        if (not isinstance(run, dict) or type(run.get("id")) is not int or run["id"] <= 0
                or run["id"] in ids or type(run.get("workflow_id")) is not int
                or run["workflow_id"] != workflow["id"]
                or run.get("head_branch") != branch or run.get("event") != "schedule"):
            raise ValueError("scheduled workflow-run identity is inconsistent")
        ids.add(run["id"])
        created = parse_time(run.get("created_at"))
        if created > now + FUTURE_SKEW:
            raise ValueError("scheduled workflow run is dated in the future")
        status, conclusion = run.get("status"), run.get("conclusion")
        if status == "completed":
            if not isinstance(conclusion, str) or not conclusion:
                raise ValueError("completed workflow run lacks a conclusion")
        elif status in {"queued", "in_progress", "waiting", "pending", "requested"}:
            if conclusion is not None:
                raise ValueError("unfinished workflow run has a conclusion")
        else:
            raise ValueError("workflow run has an unknown status")
        runs.append((created, run["id"], status, conclusion))

    latest = max(runs, key=lambda item: (item[0], item[1]))
    age = max(timedelta(0), now - latest[0])
    run_url = f"https://github.com/{repo}/actions/runs/{latest[1]}"
    if age > SUCCESS_MAX_AGE:
        raise MonitorAlert(f"last scheduled watcher run is older than eight hours: {run_url}")
    if latest[2] == "completed" and latest[3] != "success":
        raise MonitorAlert(f"latest scheduled watcher run ended {latest[3]}: {run_url}")
    if latest[2] != "completed" and age > ACTIVE_MAX_AGE:
        raise MonitorAlert(f"scheduled watcher run has not completed within two hours: {run_url}")
    successful = [run for run in runs if run[2:] == ("completed", "success")
                  and now - run[0] <= SUCCESS_MAX_AGE]
    if not successful:
        raise MonitorAlert(f"no successful scheduled watcher run in eight hours: {run_url}")
    return f"scheduled watcher healthy on {branch}; latest run: {run_url}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Exact GitHub OWNER/REPO to monitor")
    args = parser.parse_args()
    try:
        print(inspect(args.repo))
    except MonitorAlert as error:
        print(f"WATCHER ALERT: {error}", file=sys.stderr)
        return 1
    except (ValueError, OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        print(f"WATCHER UNKNOWN: unable to verify scheduled polling ({error})", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
