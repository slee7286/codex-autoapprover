# External release-watch monitor and recovery

The six-hour `upstream-watch.yml` schedule can be delayed, dropped or disabled
after repository inactivity. The read-only
[`monitor_upstream_watch.py`](../scripts/monitor_upstream_watch.py) check must
run **outside GitHub Actions** so a stalled Actions scheduler cannot suppress
its own alarm. It is prepared locally, not deployed or active. The watcher
itself must also be merged to the default branch before scheduled runs exist.

A read-only check on 2026-09-23 found `main` as the public repository's
default branch and only the CI workflow on that branch. The monitor correctly
returned exit 1 for the absent watcher. This is an activation blocker, not a
successful schedule rehearsal.

Configure an independent scheduler to run this command every 30 minutes and
alert an operator on **every nonzero exit**:

```sh
python3 scripts/monitor_upstream_watch.py --repo slee7286/codex-autoapprover
```

For a public repository the GitHub read endpoints can be called without a
token. For a private repository, supply `GH_TOKEN` through the external
scheduler's secret store with repository **Actions: read** access. Do not put
the token in command arguments or logs. The monitor only reads repository,
workflow and scheduled-run metadata. It discovers the current default branch,
requires this workflow to be active, and checks `event=schedule` runs so a
manual dispatch cannot conceal a stalled schedule. Its result is:

- Exit 0: the latest scheduled run succeeded, or is still within two hours
  of starting with another successful scheduled run in the past eight hours.
- Exit 1: a missing or inactive workflow, no scheduled run, a failed latest
  run, a run active for over two hours, or no successful schedule within eight
  hours.
- Exit 2: API/rate-limit/network or inconsistent-response trouble prevents
  verification. This also needs an operator alert; it is not a healthy result.

The eight-hour limit gives the six-hour cron two hours of delay tolerance.
Adjust the scheduler's alert routing rather than treating a manual dispatch
as a substitute heartbeat. The monitor uses the [Get a workflow](https://docs.github.com/en/rest/actions/workflows#get-a-workflow)
and [List workflow runs for a workflow](https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-workflow)
APIs; GitHub documents [schedule delay and inactivity disabling](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

On an alert, inspect the linked run, the workflow state, the repository's
default branch and GitHub Actions availability. For API errors, restore read
access or wait for rate-limit reset, then rerun the monitor; do not assume the
watcher ran while the monitor was blind. For a missing or failed schedule,
review the workflow log and official Codex release metadata, then use the
workflow's manual dispatch on the default branch after resolving the cause.
The watcher queues one unhandled stable release per successful poll, oldest
first. Continue polling until the backlog is handled; stop for independent
review if a recorded asset, npm package or source tag identity changed. A
successful manual run does not clear the monitoring alert: confirm the next
scheduled run succeeds. Discovery and repair never certify compatibility;
unreviewed or inconclusive targets remain unarmed.
