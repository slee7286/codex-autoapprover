# Codex 0.156.1 Linux candidate observation — 2026-09-23

This is **unverified candidate material**, separate from the production
manifest and `compatibility/evidence/`. It does not certify a PermissionRequest
hook, a sandbox implementation, this project's consumer binary, or Windows.
The checked-in `compatibility/candidate.json` remains the 0.156.0 baseline so
the default-branch watcher can still open a 0.156.1 candidate PR when active.

The official latest full release API returned `rust-v0.156.1`, release ID
`394258789`, published `2026-09-23T02:41:36Z`. A read-only run of
`scripts/watch_codex.py` advanced a copy of the 0.156.0 baseline under `/tmp`
and produced [unverified-candidate.json](unverified-candidate.json), including
the official release assets, seven npm package integrities, annotated tag
object and source commit. It created no branch or PR.

On native Linux x86_64, `scripts/verify_candidate_asset.py` streamed the
107,380,357-byte official musl archive and matched its official SHA-256
`aff46539a83aff86e3c62c592bce2c50d95391f9df289afaf03a50c01d14533d`;
see [asset-verification.json](asset-verification.json). A disposable npm 11.17.0
install used [package-lock.json](package-lock.json) with scripts disabled. The
exact lock and installed parent/native package identities passed
`scripts/verify_candidate_npm.py`; see
[npm-verification.json](npm-verification.json). `npm audit signatures` reported
two verified registry signatures and two verified attestations. The installed
shim passed the bounded version/help/features probes with an isolated
temporary `CODEX_HOME`; see [candidate-probe.json](candidate-probe.json).

These checks did not start an authenticated Codex session, observe a live
approval request, or run Windows. Signature audit output was observed locally
but no signed attestation bundle was retained here. All five JSON artifacts
are review material only; native live evidence and independent review remain
required before any manifest entry or ready policy.
