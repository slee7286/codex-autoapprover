#!/usr/bin/env python3
"""Inspect a bounded Codex exec JSONL trace; never certify hook compatibility.

The broker audit must independently establish the exact PermissionRequest and
one allow. This analyzer checks the CLI's machine-reported command execution,
not an agent summary or the Codex process exit status.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


MAX_TRACE_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
NON_ACTION_ITEMS = {"agent_message", "reasoning", "todo_list"}
ACTION_ITEMS = {"file_change", "mcp_tool_call", "collab_tool_call", "web_search"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def analyze(body: bytes, expected_command: str) -> dict:
    if not expected_command or "\n" in expected_command or "\r" in expected_command:
        raise ValueError("expected command must be one nonempty line")
    if not body or len(body) > MAX_TRACE_BYTES or not body.endswith(b"\n"):
        raise ValueError("Codex JSONL trace is empty, oversized or truncated")

    thread_started = turn_started = turn_completed = 0
    command_id = None
    command_completed = False
    event_count = 0
    for raw in body.splitlines():
        if not raw or len(raw) > MAX_LINE_BYTES:
            raise ValueError("Codex JSONL trace has an empty or oversized event")
        event = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise ValueError("Codex JSONL event has no type")
        event_count += 1
        kind = event["type"]
        if kind == "thread.started":
            thread_started += 1
            if event_count != 1 or not isinstance(event.get("thread_id"), str) or not event["thread_id"]:
                raise ValueError("unexpected Codex thread start")
        elif kind == "turn.started":
            turn_started += 1
            if thread_started != 1 or turn_started != 1 or turn_completed:
                raise ValueError("unexpected Codex turn start")
        elif kind == "turn.completed":
            turn_completed += 1
            if turn_started != 1 or turn_completed != 1 or not command_completed:
                raise ValueError("Codex turn completed without one successful command")
        elif kind.startswith("item."):
            if turn_started != 1 or turn_completed:
                raise ValueError("Codex item outside the single turn")
            if kind not in {"item.started", "item.updated", "item.completed"}:
                raise ValueError("unexpected Codex item event")
            item = event.get("item")
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
                raise ValueError("Codex item has no stable ID")
            item_type = item.get("type")
            if item_type in ACTION_ITEMS or item_type not in NON_ACTION_ITEMS | {"command_execution"}:
                raise ValueError("Codex ran or emitted an unexpected tool item")
            if item_type != "command_execution":
                continue
            if item.get("command") != expected_command:
                raise ValueError("Codex command differs from the exact expected command")
            if kind == "item.started":
                if command_id is not None or command_completed:
                    raise ValueError("Codex started an additional command")
                if item.get("status") != "in_progress" or item.get("exit_code") is not None:
                    raise ValueError("Codex command start is inconsistent")
                command_id = item["id"]
            elif kind == "item.updated":
                if item["id"] != command_id or command_completed:
                    raise ValueError("Codex updated an unknown or completed command")
                if item.get("status") != "in_progress" or item.get("exit_code") is not None:
                    raise ValueError("Codex command update is inconsistent")
            elif kind == "item.completed":
                if item["id"] != command_id or command_completed:
                    raise ValueError("Codex completed an unknown or repeated command")
                if item.get("status") != "completed" or type(item.get("exit_code")) is not int or item["exit_code"] != 0:
                    raise ValueError("Codex command did not complete with exit code zero")
                command_completed = True
            else:
                raise ValueError("unexpected Codex command event")
        else:
            raise ValueError("unexpected Codex event or execution error")

    if (thread_started, turn_started, turn_completed) != (1, 1, 1) or not command_completed:
        raise ValueError("Codex JSONL trace is missing a complete single-command turn")
    return {
        "schema_version": 1,
        "status": "trace-only-unverified",
        "trace_sha256": hashlib.sha256(body).hexdigest(),
        "command_sha256": hashlib.sha256(expected_command.encode()).hexdigest(),
        "command_exit_code": 0,
        "command_count": 1,
        "event_count": event_count,
    }


def read_trace(path: Path) -> bytes:
    entry = os.lstat(path)
    if not stat.S_ISREG(entry.st_mode):
        raise ValueError("trace path is not a regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as source:
        before = os.fstat(source.fileno())
        if ((before.st_dev, before.st_ino) != (entry.st_dev, entry.st_ino)
                or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > MAX_TRACE_BYTES):
            raise ValueError("trace must be a bounded, regular, singly linked file")
        body = source.read(MAX_TRACE_BYTES + 1)
        after = os.fstat(source.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if len(body) != before.st_size or identity(before) != identity(after):
            raise ValueError("Codex JSONL trace changed while reading")
    return body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--expected-command", required=True)
    args = parser.parse_args()
    report = analyze(read_trace(args.trace), args.expected_command)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
