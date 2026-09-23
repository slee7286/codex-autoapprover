#!/usr/bin/env bash
set -euo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binary="${1:-$repo/target/debug/codex-autoapprover}"
[[ -f $binary ]] || { printf 'Build codex-autoapprover first.\n' >&2; exit 1; }
test_root=$(mktemp -d /tmp/codex-autoapprover-package.XXXXXXXX)
trap 'rm -rf -- "$test_root"' EXIT
mkdir -m 700 -- "$test_root/first" "$test_root/second" "$test_root/unpacked" "$test_root/codex home"
printf 'preserve authentication and sessions\n' > "$test_root/codex home/session.txt"
session_digest=$(sha256sum < "$test_root/codex home/session.txt" | awk '{print $1}')
export CODEX_HOME="$test_root/codex home"

python3 "$repo/scripts/package_linux.py" --binary "$binary" --output-dir "$test_root/first" >/dev/null
python3 "$repo/scripts/package_linux.py" --binary "$binary" --output-dir "$test_root/second" >/dev/null
python3 "$repo/scripts/package_linux.py" --binary "$binary" --output-dir "$test_root/first" >/dev/null
first=("$test_root/first"/*.tar.gz)
second=("$test_root/second"/*.tar.gz)
[[ ${#first[@]} == 1 && ${#second[@]} == 1 ]]
cmp -- "${first[0]}" "${second[0]}"
(cd "$test_root/first" && sha256sum -c -- "$(basename -- "${first[0]}").sha256" >/dev/null)
tar -xzf "${first[0]}" -C "$test_root/unpacked"
package_dir="$test_root/unpacked/$(basename -- "${first[0]}" .tar.gz)"
[[ -d $package_dir ]]

binary_digest=$(python3 - "$package_dir" <<'PY'
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
)

install_dir="$test_root/installed space/bin"
"$package_dir/scripts/install-linux.sh" install --install-dir "$install_dir" --binary "$package_dir/bin/codex-autoapprover" --sha256 "$binary_digest" --manifest "$package_dir/compatibility/manifest.json" >/dev/null
[[ $(sha256sum < "$install_dir/codex-autoapprover" | awk '{print $1}') == "$binary_digest" ]]
"$install_dir/codex-autoapprover" verify-manifest --manifest "$package_dir/compatibility/manifest.json" >/dev/null
"$package_dir/scripts/install-linux.sh" uninstall --install-dir "$install_dir" >/dev/null
[[ ! -e $install_dir/codex-autoapprover ]]
[[ $(sha256sum < "$test_root/codex home/session.txt" | awk '{print $1}') == "$session_digest" ]]

ln -s "$binary" "$test_root/symlinked-binary"
if python3 "$repo/scripts/package_linux.py" --binary "$test_root/symlinked-binary" --output-dir "$test_root/second" >/dev/null 2>&1; then
  printf 'Packaging accepted a symlinked binary.\n' >&2
  exit 1
fi
printf 'Deterministic development archive and exact-byte install rehearsal passed.\n'
