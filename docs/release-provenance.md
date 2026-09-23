# Candidate binary provenance

The [manual provenance workflow](../.github/workflows/provenance-candidate.yml)
is prepared for the repository's protected `main` branch. It has not run. It
does not publish a GitHub Release or qualify Codex approval behavior.

The Linux and Windows jobs build native release executables from the same
checkout, run local tests, and stage each raw binary with a target-specific
SPDX build-input document, a native build observation, a two-build
reproducibility observation, and SHA-256 checksums for all four files. The
bounded `build-record.json` identifies the exact
binary/source/lockfile/manifest digests, Git revision, clean-tree status,
compiler and Cargo versions, native target and selected OS facts. It omits
hostnames and environment variables. The qualification jobs compare the
record to downloaded bytes and source and require the same compiler/Cargo
versions; they do not require the OS patch level to remain identical across
runner jobs. The reproducibility check archives the clean commit, builds it
twice in separate directories with the pinned local toolchain and offline
locked dependencies, and requires both executable digests to equal the staged
binary. Its JSON report binds the commit, canonical source digest, toolchain,
archive and executable, and is checked again after download. This establishes
byte repeatability under one host/toolchain environment; it does not establish
independent source provenance, cross-host reproducibility, or native approval
behavior. The record is self-reported review material, not proof that
the binary came from those inputs or a complete linked-component inventory.
The workflow provenance and independent review must establish that
relationship. The jobs upload seven-day **unqualified candidate** artifacts.
Separate native Linux and Windows jobs download those bytes, verify all four
digests, regenerate the SBOM against the downloaded executable and current
source, validate the build and reproducibility observations, and require
`release_gate.py --require-ready --binary` to match each executable to fresh,
reviewed evidence for that runner's native OS and the complete embedded support
manifest. Readiness requires both native Linux and Windows x86_64
certificates. The present empty manifest and pending policy cause both
qualification jobs to fail.

An independent attestation job runs after both builds, even if qualification
is still pending. It downloads the same candidates, checks their staged
digests, and uses pinned GitHub `actions/attest` to record build provenance for
the exact raw bytes and a separate SPDX SBOM attestation whose subject is the
same binary digest. These attestations prove signed statements about their
subjects; they do **not** certify native Codex
behavior or make the candidate a release. They can supply preliminary signed
provenance for later independent review, avoiding a cycle in which the gate
requires provenance before the workflow can create it. The job retains
verification bundles for 90 days and uses the `release-candidate` environment.
Only this job requests OIDC and attestation-write permissions; build and
qualification jobs have read-only repository access.
The credentialed job reads the environment settings and refuses to attest
unless there are required reviewers, self-review is disabled and deployment is
restricted to protected branches. [GitHub documents](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
that a workflow can otherwise create a named environment without protection
rules when it first uses that name.
Configure those rules before dispatch; the job itself only accepts `main`.
Repository branch protection, required CI,
code-owner review and security review also need to be enabled and verified.
The prepared workflow file does not configure those repository settings.

After an authorized run, download the candidate binary and its
matching `SHA256SUMS` from the **same run**, check the digest, and verify the
GitHub attestation while enforcing the signer workflow and source branch:

```sh
sha256sum --check SHA256SUMS
gh attestation verify ./codex-autoapprover-linux-x86_64 \
  --repo slee7286/codex-autoapprover \
  --signer-workflow slee7286/codex-autoapprover/.github/workflows/provenance-candidate.yml \
  --source-ref refs/heads/main
gh attestation verify ./codex-autoapprover-linux-x86_64 \
  --repo slee7286/codex-autoapprover \
  --signer-workflow slee7286/codex-autoapprover/.github/workflows/provenance-candidate.yml \
  --source-ref refs/heads/main \
  --predicate-type https://spdx.dev/Document/v2.3 \
  --bundle linux-sbom.json
```

Use the corresponding Windows executable name for the Windows artifact. The
verification bundle can also be passed to `gh attestation verify --bundle`.
Check the verified source commit and digest against the reviewed release record.
Retain the candidate `build-record.json` under `compatibility/evidence/` and
cite it in the native report's `consumer_build_record` check. The report's
`build_commit` must equal the record's clean Git revision. The release gate
checks the record's exact source, binary, lockfile, manifest and native target
fields; independent review must still compare it with the signed provenance
and real build run. Retain `reproducibility.json` alongside it and cite it in
`consumer_reproducibility`. The gate requires two reported rebuild digests
equal to the reviewed consumer binary and checks the report's source, commit,
host and toolchain bindings against the build record. This is structural
validation of a self-reported native run, not independent reproduction.
Only a run whose **two native qualification jobs also passed** can contribute
final release evidence. A failed qualification run may still contain useful
candidate provenance, but remains unqualified. Initial native certification
may require disposable candidate-branch builds before any unverified target is
merged to protected `main`; a signed main-branch provenance record alone does
not justify adding a manifest entry.
GitHub documents the [attestation action](https://github.com/actions/attest)
and [verification command](https://cli.github.com/manual/gh_attestation_verify).

These raw candidates are not yet consumer packages. The Linux development
archive remains unsigned and unqualified, and the Windows consumer lifecycle
is unfinished. The separate all-lockfile SPDX inventory is not the binary SBOM;
the new target-specific document records build inputs, not exact linked code
or a reviewed dependency conclusion. The two-build observation is a local
repeatability check, not independent reproducibility proof. Final release also requires exact
consumer-artifact installation and rollback, independent license/vulnerability
review, protected publishing, and explicit publication authorization.
