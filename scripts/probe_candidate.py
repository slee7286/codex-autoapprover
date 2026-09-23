#!/usr/bin/env python3
"""Non-live candidate inspection. A successful result is never certification."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

from watch_codex import version_key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--output", type=Path, default=Path("candidate-probe.json"))
    args = parser.parse_args()
    version_key(args.version)
    binary = shutil.which("codex")
    if binary is None:
        raise SystemExit("Codex executable unavailable")
    with tempfile.TemporaryDirectory() as directory:
        environment = dict(os.environ, CODEX_HOME=directory)
        for key in list(environment):
            if key.startswith("CODEX_AUTOAPPROVER_") or key in {"OPENAI_API_KEY", "CODEX_API_KEY", "GH_TOKEN", "GITHUB_TOKEN"}:
                environment.pop(key)
        results = {}
        for name, arguments in [("version", ["--version"]), ("help", ["--help"]), ("features", ["features", "list"])]:
            # Files bound memory use; workflow timeout also limits the process tree.
            with tempfile.TemporaryFile() as output:
                completed = subprocess.run([binary, *arguments], env=environment, cwd=directory,
                                           stdin=subprocess.DEVNULL, stdout=output, stderr=output, timeout=30)
                size = output.tell()
                if size > 65536:
                    raise ValueError("probe output exceeded limit")
                output.seek(0)
                text = output.read().decode("utf-8", errors="strict")
            results[name] = {"exit_code": completed.returncode}
            if completed.returncode != 0:
                raise ValueError(f"{name} probe failed; candidate remains unverified")
            if name == "version" and text.strip() != f"codex-cli {args.version}":
                raise ValueError("installed version differs from selected candidate")
    args.output.write_text(json.dumps({"codex_version": args.version, "os": platform.system(),
        "architecture": platform.machine(), "checks": results,
        "status": "non-live-probes-only", "certified": False}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
