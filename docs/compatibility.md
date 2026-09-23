# Compatibility and certification

Normal automatic approval requires an exact reviewed Codex version/OS tuple. `automatic` is now a legacy alias for `strict`; neither an environment variable nor a passing help/configuration probe can enable an unknown release. The broker independently rejects unreviewed versions.

| Target | Evidence | Normal run |
| --- | --- | --- |
| Linux / local CLI / Codex 0.151.0 | Historical reviewed isolated hook test recorded from commit 4206097 | Eligible under the historical registry; current release still needs fresh production qualification |
| Linux / Codex 0.153.0 and 0.153.4 | Inspected/requested, no retained independent live evidence | Unarmed |
| Windows / Codex 0.152.1 and 0.154.0 | Candidate implementation and synthetic tests | Unarmed |
| Windows / Codex 0.156.0 | User-reported elevated sandbox setup failure and successful unelevated Get-Location | Unarmed; no live approval-hook certification |
| Other versions / macOS / other OS or surfaces | No reviewed tuple | Unarmed |

Historical Ubuntu Expect/option-1 evidence is not a stable interface or hook certification. The Linux 0.151.0 hook record is historical evidence, not a statement that the present artifact has passed production qualification. No release artifact is currently production-qualified; [release policy](../compatibility/release-policy.json) intentionally has `ready: false`.

`verify-local-hook` is an interactive experiment with a temporary repository. Only its broker can use the candidate schema path, and only for the fixed `Bash` curl probe. It never edits the allowlist. Zero permission events, dirty state, multiple allows, command mismatch, errors or incomplete cleanup are inconclusive/failing evidence.

Before public release, bind the manifest and runtime to exact OS build/distro, architecture, sandbox, local surface, schema and executable identity. Broad OS-family matching and version-string trust alone are insufficient. Enforce unsupported-environment detection; a supplied enum value is not host attestation. See [production plan](production-plan.md) for native acceptance criteria and required evidence.

[Release discovery](../scripts/watch_codex.py) stores unverified candidates separately. Discovery, candidate probes, code repair and certification are separate steps. No upstream announcement or automated code change can self-certify a release.
