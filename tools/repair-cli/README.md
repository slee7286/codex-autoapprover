# Pinned repair worker CLI

The repair workflow uses this exact npm lock for its own Codex CLI. It verifies
the lock against current official registry metadata, installs with scripts
disabled, checks registry signatures and attestations, verifies the installed
package set, and checks the CLI version **before** providing the dedicated
repair API key to the bounded worker. This tool version is separate from the
upstream release candidate being examined; it does not certify approval-hook
compatibility.

To update the worker, change the exact `@openai/codex` version in
`package.json`, regenerate `package-lock.json` with
`npm install --package-lock-only --save-exact --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org`,
and run `python3 scripts/verify_repair_cli.py --root tools/repair-cli` from the
repository root. Review the seven pinned package identities and the workflow
version assertion together. The repair key is a dedicated, limited credential;
the same-user agent process can still read its temporary authentication state,
so the key must not be a production or signing credential.
