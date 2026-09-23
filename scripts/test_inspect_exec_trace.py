import json
from pathlib import Path
import tempfile
import unittest

import inspect_exec_trace as trace


COMMAND = "curl -I https://example.com"


def event(kind, **fields):
    return {"type": kind, **fields}


def item(kind, item_type="command_execution", **fields):
    return event(kind, item={"id": "item_1", "type": item_type, **fields})


def valid_events():
    return [
        event("thread.started", thread_id="thread-1"),
        event("turn.started"),
        item("item.started", command=COMMAND, status="in_progress", exit_code=None),
        item("item.completed", command=COMMAND, status="completed", exit_code=0),
        event("turn.completed"),
    ]


def jsonl(events):
    return ("\n".join(json.dumps(value) for value in events) + "\n").encode()


class ExecTraceTests(unittest.TestCase):
    def test_single_exact_successful_command_produces_non_promoting_report(self):
        report = trace.analyze(jsonl(valid_events()), COMMAND)
        self.assertEqual(report["status"], "trace-only-unverified")
        self.assertEqual(report["command_count"], 1)
        self.assertEqual(report["command_exit_code"], 0)
        self.assertNotIn(COMMAND, json.dumps(report))

    def test_missing_changed_extra_or_failed_command_is_rejected(self):
        cases = []
        original = valid_events()
        cases.append(original[:2] + original[-1:])
        cases.append(original[:3] + [item("item.completed", command="true", status="completed", exit_code=0)] + original[-1:])
        cases.append(original[:4] + [item("item.started", command=COMMAND, status="in_progress", exit_code=None)] + original[-1:])
        cases.append(original[:3] + [item("item.completed", command=COMMAND, status="failed", exit_code=1)] + original[-1:])
        cases.append(original[:3] + [item("item.completed", command=COMMAND, status="completed", exit_code=True)] + original[-1:])
        for events in cases:
            with self.subTest(events=events), self.assertRaises(ValueError):
                trace.analyze(jsonl(events), COMMAND)

    def test_extra_tool_errors_duplicate_keys_and_truncation_are_rejected(self):
        for item_type in trace.ACTION_ITEMS:
            events = valid_events()
            events.insert(4, item("item.completed", item_type))
            with self.subTest(item_type=item_type), self.assertRaises(ValueError):
                trace.analyze(jsonl(events), COMMAND)
        events = valid_events()
        events.insert(4, event("error", message="execution failed"))
        with self.assertRaises(ValueError):
            trace.analyze(jsonl(events), COMMAND)
        with self.assertRaises(ValueError):
            trace.analyze(jsonl(valid_events())[:-1], COMMAND)
        with self.assertRaises(ValueError):
            trace.analyze(b'{"type":"turn.started","type":"turn.completed"}\n', COMMAND)

    def test_trace_read_refuses_a_symlink_and_accepts_a_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            path.write_bytes(jsonl(valid_events()))
            self.assertEqual(trace.read_trace(path), jsonl(valid_events()))
            link = Path(directory) / "linked.jsonl"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                trace.read_trace(link)

    def test_command_update_must_remain_in_progress(self):
        events = valid_events()
        events.insert(3, item("item.updated", command=COMMAND, status="failed", exit_code=1))
        with self.assertRaises(ValueError):
            trace.analyze(jsonl(events), COMMAND)


if __name__ == "__main__":
    unittest.main()
