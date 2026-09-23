# Foundation validation — 2026-09-23

These checks validate the release-preparation changes, not live Codex approval compatibility.

| Check | Result |
| --- | --- |
| `cargo test --locked --all-targets` on Linux | 57 unit tests and 22 integration tests passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed |
| `cargo check --locked --target x86_64-pc-windows-msvc --all-targets` | Passed; compile only |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | 8 tests passed |
| Workflow YAML parsing and `git diff --check` | Passed; workflows not run on GitHub |
| Read-only real upstream watcher test | Detected official `rust-v0.156.0`, release id `394061815`; temporary metadata only, no PR created |
| `release_gate.py` with pending policy | Valid policy, remains blocked |
| `release_gate.py --require-ready --binary ...` | Correctly rejected incomplete qualification |

The first sandboxed Rust test run could not open Unix sockets. Running the tests with host socket access resolved that environment restriction. One intermediate integration run saw an inconclusive version probe; subsequent complete runs passed. Keep capability/version probing under the concurrency and timeout stress workstream rather than treating a few passing runs as exhaustive evidence.

The first live upstream API test exceeded the 4 MiB response cap at large page sizes, so the watcher used five releases per page. Later the repository exceeded 100 releases in its first twenty pages; a full-history scan then failed closed on its page limit. The watcher now uses GitHub's single latest-full-release endpoint for normal polling. On an update it scans five at a time back to the recorded tag, rejecting a missing prior tag, changed identity or multiple new stable releases for manual recovery. Network, redirect and response-size errors still fail explicitly; no compatibility is enabled.

Not executed here: native Windows binaries, PowerShell 5.1/7 installer tests, real hook approval on any new tuple, GitHub scheduled jobs/PR creation, automated repair worker, clean-machine packaging, signing, consumer rollback or external independent review. They remain production blockers in the plan. No user Codex settings were modified during these tests; no public release was published.
