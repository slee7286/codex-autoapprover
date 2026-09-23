import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import probe_candidate


@unittest.skipUnless(os.name == "posix", "executable fixture requires a POSIX shebang")
class ProbeCandidateTests(unittest.TestCase):
    def test_exact_stdout_version_accepts_separate_stderr_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "codex"
            binary.write_text("#!/usr/bin/env python3\n"
                              "import sys\n"
                              "print('WARNING: diagnostic', file=sys.stderr)\n"
                              "if sys.argv[1:] == ['--version']:\n"
                              "    print('codex-cli 0.156.0')\n"
                              "else:\n"
                              "    print('non-live probe')\n")
            binary.chmod(0o700)
            report = root / "report.json"
            with patch("sys.argv", ["probe_candidate.py", "0.156.0", "--binary",
                                    str(binary), "--output", str(report)]):
                probe_candidate.main()
            data = json.loads(report.read_text())
            self.assertEqual(data["checks"]["version"]["exit_code"], 0)
            self.assertGreater(data["checks"]["version"]["stderr_bytes"], 0)
            self.assertFalse(data["certified"])


if __name__ == "__main__":
    unittest.main()
