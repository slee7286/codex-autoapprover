"""Synthetic external-monitor checks; these do not prove a GitHub schedule ran."""

from datetime import datetime, timedelta, timezone
import io
import urllib.error
import unittest

import monitor_upstream_watch as monitor


NOW = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)
REPO = "example/release-monitor"
BASE = f"https://api.github.com/repos/{REPO}"


def run(identifier, age_hours, status="completed", conclusion="success", branch="main"):
    return {
        "id": identifier, "workflow_id": 17, "head_branch": branch,
        "event": "schedule", "status": status, "conclusion": conclusion,
        "created_at": (NOW - timedelta(hours=age_hours)).isoformat(),
    }


def fixture(runs=None):
    records = {
        BASE: {"full_name": REPO, "default_branch": "main",
               "archived": False, "disabled": False},
        f"{BASE}/actions/workflows/{monitor.WORKFLOW_FILE}": {
            "id": 17, "path": monitor.WORKFLOW_PATH, "state": "active",
        },
    }
    query = "branch=main&event=schedule&per_page=20&page=1"
    records[f"{BASE}/actions/workflows/{monitor.WORKFLOW_FILE}/runs?{query}"] = {
        "total_count": len(runs or []), "workflow_runs": runs or [],
    }
    return records


class MonitorTests(unittest.TestCase):
    def inspect(self, records):
        return monitor.inspect(REPO, records.__getitem__, NOW)

    def test_recent_success_is_healthy(self):
        result = self.inspect(fixture([run(20, 1), run(19, 7)]))
        self.assertIn("healthy on main", result)
        self.assertIn("/actions/runs/20", result)

    def test_delayed_failed_and_disabled_schedules_alert(self):
        cases = [
            (fixture([]), "no scheduled"),
            (fixture([run(20, 9)]), "older than eight hours"),
            (fixture([run(21, 1, conclusion="failure"), run(20, 7)]), "ended failure"),
            (fixture([run(21, 3, status="in_progress", conclusion=None), run(20, 7)]),
             "not completed within two hours"),
            (fixture([run(21, .25, status="in_progress", conclusion=None)]),
             "no successful scheduled"),
        ]
        for records, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(monitor.MonitorAlert, reason):
                self.inspect(records)
        disabled = fixture([run(20, 1)])
        disabled[f"{BASE}/actions/workflows/{monitor.WORKFLOW_FILE}"]["state"] = "disabled_inactivity"
        with self.assertRaisesRegex(monitor.MonitorAlert, "not active"):
            self.inspect(disabled)
        archived = fixture([run(20, 1)])
        archived[BASE]["archived"] = True
        with self.assertRaisesRegex(monitor.MonitorAlert, "archived"):
            self.inspect(archived)

    def test_recent_run_in_progress_uses_previous_scheduled_success(self):
        result = self.inspect(fixture([
            run(21, .25, status="in_progress", conclusion=None), run(20, 6.5),
        ]))
        self.assertIn("/actions/runs/21", result)

    def test_missing_workflow_is_an_operational_alert(self):
        records = fixture([run(20, 1)])
        workflow_url = f"{BASE}/actions/workflows/{monitor.WORKFLOW_FILE}"

        def fetcher(url):
            if url == workflow_url:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            return records[url]

        with self.assertRaisesRegex(monitor.MonitorAlert, "absent from the default branch"):
            monitor.inspect(REPO, fetcher, NOW)

    def test_manual_or_wrong_branch_run_cannot_mask_missing_schedule(self):
        for change in (lambda item: item.update(event="workflow_dispatch"),
                       lambda item: item.update(head_branch="feature"),
                       lambda item: item.update(workflow_id=99)):
            records = fixture([run(20, 1)])
            listing = next(value for key, value in records.items() if key.endswith("/runs?branch=main&event=schedule&per_page=20&page=1"))
            change(listing["workflow_runs"][0])
            with self.assertRaisesRegex(ValueError, "identity is inconsistent"):
                self.inspect(records)

    def test_api_identity_and_clock_anomalies_are_unknown(self):
        records = fixture([run(20, 1)])
        records[BASE]["default_branch"] = "other"
        key = next(key for key in records if "/runs?" in key)
        records[key.replace("branch=main", "branch=other")] = records.pop(key)
        with self.assertRaisesRegex(ValueError, "identity is inconsistent"):
            self.inspect(records)
        records = fixture([run(20, -1)])
        with self.assertRaisesRegex(ValueError, "future"):
            self.inspect(records)
        records = fixture([run(20, 1)])
        records[f"{BASE}/actions/workflows/{monitor.WORKFLOW_FILE}"]["path"] = ".github/workflows/other.yml"
        with self.assertRaisesRegex(ValueError, "wrong workflow"):
            self.inspect(records)

    def test_rate_limit_and_duplicate_json_fail_closed(self):
        url = BASE

        def rate_limited(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 429, "rate limited", {}, None)

        with self.assertRaises(urllib.error.HTTPError) as raised:
            monitor.fetch_json(url, open_url=rate_limited)
        raised.exception.close()

        class Response:
            status = 200

            def __init__(self, request):
                self.request = request
                self.stream = io.BytesIO(b'{"state":"active","state":"disabled"}')

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def geturl(self):
                return self.request.full_url

            def read(self, size):
                return self.stream.read(size)

        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            monitor.fetch_json(url, open_url=lambda request, timeout: Response(request))


if __name__ == "__main__":
    unittest.main()
