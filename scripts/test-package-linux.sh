#!/usr/bin/env bash
set -euo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binary="${1:-$repo/target/debug/codex-autoapprover}"
[[ -f $binary ]] || { printf 'Build codex-autoapprover first.\n' >&2; exit 1; }
test_root=$(mktemp -d /tmp/codex-autoapprover-package.XXXXXXXX)
trap 'rm -rf -- "$test_root"' EXIT
mkdir -m 700 -- "$test_root/first" "$test_root/second" "$test_root/upgrade" \
  "$test_root/unpacked" "$test_root/unpacked-upgrade" "$test_root/codex home"
printf 'preserve authentication and sessions\n' > "$test_root/codex home/session.txt"
session_digest=$(sha256sum < "$test_root/codex home/session.txt" | awk '{print $1}')
export CODEX_HOME="$test_root/codex home"

python3 "$repo/scripts/package_linux.py" --binary "$binary" --output-dir "$test_root/first" >/dev/null
python3 "$repo/scripts/package_linux.py" --binary "$binary" --output-dir "$test_root/second" >/dev/null
python3 "$repo/scripts/package_linux.py" --binary "$binary" --output-dir "$test_root/first" >/dev/null
cp -- "$binary" "$test_root/upgrade-binary"
printf '\0' >> "$test_root/upgrade-binary"
chmod 700 -- "$test_root/upgrade-binary"
python3 "$repo/scripts/package_linux.py" --binary "$test_root/upgrade-binary" --output-dir "$test_root/upgrade" >/dev/null
first=("$test_root/first"/*.tar.gz)
second=("$test_root/second"/*.tar.gz)
upgrade=("$test_root/upgrade"/*.tar.gz)
[[ ${#first[@]} == 1 && ${#second[@]} == 1 && ${#upgrade[@]} == 1 ]]
cmp -- "${first[0]}" "${second[0]}"
if cmp -s -- "${first[0]}" "${upgrade[0]}"; then
  printf 'Byte-distinct upgrade produced an identical archive.\n' >&2
  exit 1
fi
(cd "$test_root/first" && sha256sum -c -- "$(basename -- "${first[0]}").sha256" >/dev/null)
(cd "$test_root/upgrade" && sha256sum -c -- "$(basename -- "${upgrade[0]}").sha256" >/dev/null)
tar -xzf "${first[0]}" -C "$test_root/unpacked"
tar -xzf "${upgrade[0]}" -C "$test_root/unpacked-upgrade"
package_dir="$test_root/unpacked/$(basename -- "${first[0]}" .tar.gz)"
upgrade_dir="$test_root/unpacked-upgrade/$(basename -- "${upgrade[0]}" .tar.gz)"
[[ -d $package_dir && -d $upgrade_dir ]]

artifact_binary_digest() {
  python3 - "$1" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
metadata = json.loads((root / "artifact.json").read_text())
assert metadata["release_status"] == "unqualified-development-rehearsal"
for name, expected in metadata["file_sha256"].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected
assert metadata["binary_sha256"] == metadata["file_sha256"]["bin/codex-autoapprover"]
print(metadata["binary_sha256"])
PY
}
binary_digest=$(artifact_binary_digest "$package_dir")
upgrade_digest=$(artifact_binary_digest "$upgrade_dir")
[[ $binary_digest != "$upgrade_digest" ]]

install_dir="$test_root/installed space/bin"
"$package_dir/scripts/install-linux.sh" install --install-dir "$install_dir" --binary "$package_dir/bin/codex-autoapprover" --sha256 "$binary_digest" --manifest "$package_dir/compatibility/manifest.json" >/dev/null
[[ $(sha256sum < "$install_dir/codex-autoapprover" | awk '{print $1}') == "$binary_digest" ]]
"$install_dir/codex-autoapprover" verify-manifest --manifest "$package_dir/compatibility/manifest.json" >/dev/null
"$package_dir/scripts/install-linux.sh" install --install-dir "$install_dir" --binary "$package_dir/bin/codex-autoapprover" --sha256 "$binary_digest" --manifest "$package_dir/compatibility/manifest.json" >/dev/null
[[ $("$package_dir/scripts/install-linux.sh" status --install-dir "$install_dir") == *"Previous: none"* ]]
"$upgrade_dir/scripts/install-linux.sh" install --install-dir "$install_dir" --binary "$upgrade_dir/bin/codex-autoapprover" --sha256 "$upgrade_digest" --manifest "$upgrade_dir/compatibility/manifest.json" >/dev/null
[[ $(sha256sum < "$install_dir/codex-autoapprover" | awk '{print $1}') == "$upgrade_digest" ]]
status=$("$upgrade_dir/scripts/install-linux.sh" status --install-dir "$install_dir")
[[ $status == *"Current: $upgrade_digest"* && $status == *"Previous: $binary_digest"* ]]
"$upgrade_dir/scripts/install-linux.sh" rollback --install-dir "$install_dir" >/dev/null
[[ $(sha256sum < "$install_dir/codex-autoapprover" | awk '{print $1}') == "$binary_digest" ]]
status=$("$upgrade_dir/scripts/install-linux.sh" status --install-dir "$install_dir")
[[ $status == *"Current: $binary_digest"* && $status == *"Previous: $upgrade_digest"* ]]
"$upgrade_dir/scripts/install-linux.sh" uninstall --install-dir "$install_dir" >/dev/null
[[ ! -e $install_dir/codex-autoapprover && ! -e $install_dir/.codex-autoapprover-releases ]]
[[ $(sha256sum < "$test_root/codex home/session.txt" | awk '{print $1}') == "$session_digest" ]]

ln -s "$binary" "$test_root/symlinked-binary"
if python3 "$repo/scripts/package_linux.py" --binary "$test_root/symlinked-binary" --output-dir "$test_root/second" >/dev/null 2>&1; then
  printf 'Packaging accepted a symlinked binary.\n' >&2
  exit 1
fi
printf 'Deterministic development archives and exact-byte install/upgrade/rollback/uninstall rehearsal passed.\n'
