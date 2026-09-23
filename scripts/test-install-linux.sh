#!/usr/bin/env bash
set -euo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
installer="$repo/scripts/install-linux.sh"
source_binary="${1:-$repo/target/debug/codex-autoapprover}"
[[ -f $source_binary ]] || { printf 'Build codex-autoapprover first.\n' >&2; exit 1; }
test_root=$(mktemp -d /tmp/codex-autoapprover-install.XXXXXXXX)
trap 'rm -rf -- "$test_root"' EXIT
install_dir="$test_root/space & unicode-测试/bin"
codex_home="$test_root/codex home"
mkdir -m 700 -- "$codex_home"
export CODEX_HOME="$codex_home"
printf 'auth and sessions stay untouched\n' > "$codex_home/session.txt"
original_config=$(sha256sum < "$codex_home/session.txt" | awk '{print $1}')
cp -- "$source_binary" "$test_root/v1"
cp -- "$source_binary" "$test_root/v2"
printf '\0' >> "$test_root/v2"
chmod 700 -- "$test_root/v1" "$test_root/v2"
sha1=$(sha256sum < "$test_root/v1" | awk '{print $1}')
sha2=$(sha256sum < "$test_root/v2" | awk '{print $1}')
manifest="$repo/compatibility/manifest.json"

expect_fail() {
  if "$@" >/dev/null 2>&1; then printf 'Unexpected success: %s\n' "$*" >&2; exit 1; fi
}
expect_fail "$installer" install --install-dir "$install_dir" --binary "$test_root/v1" --sha256 "$(printf '0%.0s' {1..64})" --manifest "$manifest"
[[ ! -e $install_dir ]] || { printf 'Bad hash created destination.\n' >&2; exit 1; }
printf '{}\n' > "$test_root/wrong-manifest.json"
expect_fail "$installer" install --install-dir "$install_dir" --binary "$test_root/v1" --sha256 "$sha1" --manifest "$test_root/wrong-manifest.json"
[[ ! -e $install_dir/codex-autoapprover ]] || { printf 'Bad manifest selected an artifact.\n' >&2; exit 1; }

"$installer" install --install-dir "$install_dir" --binary "$test_root/v1" --sha256 "$sha1" --manifest "$manifest"
"$install_dir/codex-autoapprover" verify-manifest --manifest "$manifest" >/dev/null
[[ $("$installer" status --install-dir "$install_dir") == *"Current: $sha1"* ]]
expect_fail "$installer" install --install-dir "$install_dir" --binary "$test_root/v1" --sha256 "$sha1" --manifest "$test_root/wrong-manifest.json"
[[ $("$installer" status --install-dir "$install_dir") == *"Current: $sha1"* ]]
"$installer" install --install-dir "$install_dir" --binary "$test_root/v1" --sha256 "$sha1" --manifest "$manifest"
[[ ! -e $install_dir/.codex-autoapprover-previous ]]
"$installer" install --install-dir "$install_dir" --binary "$test_root/v2" --sha256 "$sha2" --manifest "$manifest"
status=$("$installer" status --install-dir "$install_dir")
[[ $status == *"Current: $sha2"* && $status == *"Previous: $sha1"* ]]

# An interrupted upgrade is completed from its journal at each pointer boundary.
printf '%s\n%s\n' "$sha1" "$sha2" > "$install_dir/.codex-autoapprover-install-journal"
status=$("$installer" status --install-dir "$install_dir")
[[ $status == *"Current: $sha1"* && $status == *"Previous: $sha2"* ]]
[[ ! -e $install_dir/.codex-autoapprover-install-journal ]]
printf '%s\n%s\n' "$sha2" "$sha1" > "$install_dir/.codex-autoapprover-install-journal"
rm -- "$install_dir/.codex-autoapprover-previous"
ln -s ".codex-autoapprover-releases/$sha1/codex-autoapprover" "$install_dir/.codex-autoapprover-previous"
status=$("$installer" status --install-dir "$install_dir")
[[ $status == *"Current: $sha2"* && $status == *"Previous: $sha1"* ]]
printf '%s\n%s\n' "$sha1" "$sha2" > "$install_dir/.codex-autoapprover-install-journal"
rm -- "$install_dir/.codex-autoapprover-previous" "$install_dir/codex-autoapprover"
ln -s ".codex-autoapprover-releases/$sha2/codex-autoapprover" "$install_dir/.codex-autoapprover-previous"
ln -s ".codex-autoapprover-releases/$sha1/codex-autoapprover" "$install_dir/codex-autoapprover"
status=$("$installer" status --install-dir "$install_dir")
[[ $status == *"Current: $sha1"* && $status == *"Previous: $sha2"* ]]
[[ ! -e $install_dir/.codex-autoapprover-install-journal ]]
"$installer" rollback --install-dir "$install_dir" >/dev/null

# Recovery must not overwrite an unrelated file placed at a managed pointer.
printf '%s\n%s\n' "$sha1" "$sha2" > "$install_dir/.codex-autoapprover-install-journal"
rm -- "$install_dir/codex-autoapprover"
printf 'unrelated\n' > "$install_dir/codex-autoapprover"
expect_fail "$installer" status --install-dir "$install_dir"
[[ $(cat -- "$install_dir/codex-autoapprover") == unrelated ]]
[[ -f $install_dir/.codex-autoapprover-install-journal ]]
rm -- "$install_dir/codex-autoapprover"
ln -s ".codex-autoapprover-releases/$sha2/codex-autoapprover" "$install_dir/codex-autoapprover"
"$installer" status --install-dir "$install_dir" >/dev/null
"$installer" rollback --install-dir "$install_dir" >/dev/null
printf 'invalid\n' > "$install_dir/.codex-autoapprover-install-journal"
expect_fail "$installer" status --install-dir "$install_dir"
rm -- "$install_dir/.codex-autoapprover-install-journal"
printf '%s\n%s\n' "$sha1" "$sha2" > "$install_dir/.codex-autoapprover-install-journal"
printf '%s\n%s\n' "$sha1" "$sha2" > "$install_dir/.codex-autoapprover-rollback-journal"
expect_fail "$installer" status --install-dir "$install_dir"
rm -- "$install_dir/.codex-autoapprover-install-journal" "$install_dir/.codex-autoapprover-rollback-journal"

current_target=$(readlink -- "$install_dir/codex-autoapprover")
rm -- "$install_dir/codex-autoapprover"
ln -s "$current_target"$'\n' "$install_dir/codex-autoapprover"
expect_fail "$installer" status --install-dir "$install_dir"
rm -- "$install_dir/codex-autoapprover"
ln -s "$current_target" "$install_dir/codex-autoapprover"
"$installer" rollback --install-dir "$install_dir"
status=$("$installer" status --install-dir "$install_dir")
[[ $status == *"Current: $sha1"* && $status == *"Previous: $sha2"* ]]

# Replaying an interrupted rollback journal finishes the requested pointer swap.
printf '%s\n%s\n' "$sha2" "$sha1" > "$install_dir/.codex-autoapprover-rollback-journal"
status=$("$installer" status --install-dir "$install_dir")
[[ $status == *"Current: $sha2"* && $status == *"Previous: $sha1"* ]]
[[ ! -e $install_dir/.codex-autoapprover-rollback-journal ]]
printf 'tamper' >> "$install_dir/.codex-autoapprover-releases/$sha2/codex-autoapprover"
expect_fail "$installer" status --install-dir "$install_dir"
cp -- "$test_root/v2" "$install_dir/.codex-autoapprover-releases/$sha2/codex-autoapprover"
printf 'unexpected\n' > "$install_dir/.codex-autoapprover-releases/$sha1/extra"
expect_fail "$installer" uninstall --install-dir "$install_dir"
[[ -L $install_dir/codex-autoapprover ]]
rm -- "$install_dir/.codex-autoapprover-releases/$sha1/extra"
"$installer" uninstall --install-dir "$install_dir"
[[ ! -e $install_dir/codex-autoapprover && ! -e $install_dir/.codex-autoapprover-releases ]]
[[ $(sha256sum < "$codex_home/session.txt" | awk '{print $1}') == "$original_config" ]]

"$installer" install --install-dir "$install_dir" --binary "$test_root/v1" --sha256 "$sha1" --manifest "$manifest"
mkdir -m 700 -- "$install_dir/.codex-autoapprover-releases/.stage.interrupted"
cp -- "$test_root/v1" "$install_dir/.codex-autoapprover-releases/.stage.interrupted/codex-autoapprover"
"$installer" status --install-dir "$install_dir" >/dev/null
[[ ! -e $install_dir/.codex-autoapprover-releases/.stage.interrupted ]]
printf 'codex-autoapprover-uninstall-v1\n' > "$install_dir/.codex-autoapprover-uninstall-journal"
rm -- "$install_dir/codex-autoapprover" "$install_dir/.codex-autoapprover-releases/$sha1/codex-autoapprover"
"$installer" uninstall --install-dir "$install_dir"
[[ ! -e $install_dir/.codex-autoapprover-releases && ! -e $install_dir/.codex-autoapprover-uninstall-journal ]]
[[ $(sha256sum < "$codex_home/session.txt" | awk '{print $1}') == "$original_config" ]]

# An interrupted first install has no old release but still finishes safely.
first_recovery="$test_root/first-install-recovery"
mkdir -m 700 -- "$first_recovery" "$first_recovery/.codex-autoapprover-releases"
printf 'codex-autoapprover-linux-installer-v1\n' > "$first_recovery/.codex-autoapprover-owned"
mkdir -m 700 -- "$first_recovery/.codex-autoapprover-releases/$sha1"
cp -- "$test_root/v1" "$first_recovery/.codex-autoapprover-releases/$sha1/codex-autoapprover"
chmod 700 -- "$first_recovery/.codex-autoapprover-releases/$sha1/codex-autoapprover"
printf '%s\nnone\n' "$sha1" > "$first_recovery/.codex-autoapprover-install-journal"
status=$("$installer" status --install-dir "$first_recovery")
[[ $status == *"Current: $sha1"* && $status == *"Previous: none"* ]]
[[ ! -e $first_recovery/.codex-autoapprover-install-journal ]]
"$installer" uninstall --install-dir "$first_recovery" >/dev/null

unmanaged="$test_root/unmanaged"
mkdir -m 700 -- "$unmanaged"
printf 'unrelated\n' > "$unmanaged/codex-autoapprover"
expect_fail "$installer" install --install-dir "$unmanaged" --binary "$test_root/v1" --sha256 "$sha1" --manifest "$manifest"
[[ $(cat "$unmanaged/codex-autoapprover") == unrelated ]]
journal_only="$test_root/journal-without-marker"
mkdir -m 700 -- "$journal_only"
printf '%s\nnone\n' "$sha1" > "$journal_only/.codex-autoapprover-install-journal"
expect_fail "$installer" status --install-dir "$journal_only"
[[ -f $journal_only/.codex-autoapprover-install-journal ]]
ln -s "$unmanaged" "$test_root/symlinked"
expect_fail "$installer" install --install-dir "$test_root/symlinked" --binary "$test_root/v1" --sha256 "$sha1" --manifest "$manifest"
printf 'Linux artifact install/upgrade/rollback/uninstall tests passed.\n'
