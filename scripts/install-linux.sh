#!/usr/bin/env bash
# Install a separately authenticated Linux release artifact. This script never edits CODEX_HOME.
set -euo pipefail
umask 077

die() { printf 'codex-autoapprover installer: %s\n' "$*" >&2; exit 1; }
usage() {
  cat >&2 <<'EOF'
Usage: install-linux.sh install --binary FILE --sha256 HEX --manifest FILE [--install-dir DIR]
       install-linux.sh rollback|uninstall|status [--install-dir DIR]
The expected SHA-256 must come from an independently authenticated release record.
EOF
  exit 2
}

[[ $# -ge 1 ]] || usage
action=$1
shift
case "$action" in install|rollback|uninstall|status) ;; *) usage ;; esac
install_dir="${HOME:?}/.local/bin"
binary=''
expected=''
manifest=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir|--binary|--sha256|--manifest)
      [[ $# -ge 2 ]] || usage
      case "$1" in
        --install-dir) install_dir=$2 ;;
        --binary) binary=$2 ;;
        --sha256) expected=$2 ;;
        --manifest) manifest=$2 ;;
      esac
      shift 2 ;;
    *) usage ;;
  esac
done
[[ $(uname -s) == Linux ]] || die 'native Linux is required'
[[ $install_dir == /* && $install_dir != *$'\n'* ]] || die 'install directory must be an absolute path without newlines'
if [[ $action == install ]]; then
  [[ -n $binary && -n $manifest && $expected =~ ^[0-9a-f]{64}$ ]] || usage
  [[ -f $binary && ! -L $binary ]] || die 'artifact is missing, a symlink, or not a regular file'
  [[ -f $manifest && ! -L $manifest ]] || die 'manifest is missing, a symlink, or not a regular file'
else
  [[ -z $binary && -z $expected && -z $manifest ]] || usage
fi
for tool in flock sha256sum timeout stat readlink mktemp; do
  command -v "$tool" >/dev/null || die "missing required command: $tool"
done

current_uid=$(id -u)
check_directory() {
  local dir=$1 owner mode
  [[ -d $dir && ! -L $dir ]] || die "unsafe directory: $dir"
  owner=$(stat -c %u -- "$dir")
  mode=$(stat -c %a -- "$dir")
  [[ $owner == "$current_uid" || $owner == 0 ]] || die "directory owned by another user: $dir"
  if (( (8#$mode & 0022) != 0 )); then
    # Root-owned sticky shared ancestors, such as /tmp, cannot be renamed by peers.
    (( owner == 0 && (8#$mode & 01000) != 0 )) || die "writable directory chain: $dir"
  fi
}
ensure_directory_chain() {
  local segment path=/
  check_directory /
  local -a pieces
  IFS=/ read -ra pieces <<< "${install_dir#/}"
  for segment in "${pieces[@]}"; do
    [[ -n $segment && $segment != . && $segment != .. ]] || die 'noncanonical install directory'
    path="${path%/}/$segment"
    if [[ ! -e $path && ! -L $path ]]; then mkdir -m 700 -- "$path"; fi
    check_directory "$path"
  done
  [[ $path == "$install_dir" ]] || die 'noncanonical install directory'
  [[ $(stat -c %u -- "$install_dir") == "$current_uid" ]] || die 'install directory is not owned by the caller'
}
digest_file() { sha256sum < "$1" | awk '{print $1}'; }
assert_release() {
  local digest=$1 file="$release_root/$1/codex-autoapprover"
  [[ $digest =~ ^[0-9a-f]{64}$ ]] || die 'invalid release digest'
  [[ -d $release_root/$digest && ! -L $release_root/$digest ]] || die "missing release: $digest"
  check_directory "$release_root/$digest"
  [[ -f $file && ! -L $file ]] || die "unsafe release file: $digest"
  [[ $(stat -c %u -- "$file") == "$current_uid" ]] || die "release owned by another user: $digest"
  [[ $(stat -c %h -- "$file") == 1 ]] || die "hardlinked release file: $digest"
  local mode
  mode=$(stat -c %a -- "$file")
  (( (8#$mode & 0022) == 0 )) || die "writable release file: $digest"
  [[ $(digest_file "$file") == "$digest" ]] || die "installed release digest mismatch: $digest"
}
pointer_digest() {
  local pointer=$1 target digest
  if [[ ! -e $pointer && ! -L $pointer ]]; then printf ''; return; fi
  [[ -L $pointer ]] || die "unmanaged or unsafe install path: $pointer"
  # The sentinel preserves trailing newlines so a malformed symlink cannot alias a valid target.
  target=$(readlink -n -- "$pointer"; printf '.')
  target=${target%.}
  [[ $target =~ ^\.codex-autoapprover-releases/([0-9a-f]{64})/codex-autoapprover$ ]] || die "unexpected install link: $pointer"
  digest=${BASH_REMATCH[1]}
  assert_release "$digest"
  printf '%s' "$digest"
}
set_pointer() {
  local pointer=$1 digest=$2 temp="$install_dir/.codex-autoapprover-link.$BASHPID.$RANDOM"
  [[ ! -e $temp && ! -L $temp ]] || die 'temporary link collision'
  ln -s ".codex-autoapprover-releases/$digest/codex-autoapprover" "$temp"
  if ! mv -Tf -- "$temp" "$pointer"; then
    rm -- "$temp"
    die "could not select release at $pointer"
  fi
}
check_marker() {
  if [[ ! -e $marker && ! -L $marker ]]; then
    [[ ! -e $current && ! -L $current && ! -e $previous && ! -L $previous && ! -e $release_root && ! -L $release_root ]] || die 'existing unmanaged installation; refusing to replace it'
    if [[ $action == install ]]; then printf 'codex-autoapprover-linux-installer-v1\n' > "$marker"; fi
    return
  fi
  [[ -f $marker && ! -L $marker && $(stat -c %u -- "$marker") == "$current_uid" && $(stat -c %h -- "$marker") == 1 && $(stat -c %s -- "$marker") -le 128 ]] || die 'unsafe install marker'
  [[ $(cat -- "$marker") == codex-autoapprover-linux-installer-v1 ]] || die 'unknown install marker'
}
cleanup_stages() {
  local stage entry
  shopt -s nullglob
  for stage in "$release_root"/.stage.*; do
    [[ -d $stage && ! -L $stage ]] || die "unsafe interrupted stage: $stage"
    check_directory "$stage"
    for entry in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
      [[ -e $entry || -L $entry ]] || continue
      [[ $entry == "$stage/codex-autoapprover" && -f $entry && ! -L $entry ]] || die "unexpected interrupted stage contents: $entry"
      rm -- "$entry"
    done
    rmdir -- "$stage"
  done
  shopt -u nullglob
}
recover_rollback() {
  [[ -e $journal || -L $journal ]] || return 0
  [[ -f $journal && ! -L $journal && $(stat -c %u -- "$journal") == "$current_uid" && $(stat -c %h -- "$journal") == 1 && $(stat -c %s -- "$journal") -le 130 ]] || die 'unsafe rollback journal'
  local -a digests
  mapfile -t digests < "$journal"
  [[ ${#digests[@]} == 2 && ${digests[0]} =~ ^[0-9a-f]{64}$ && ${digests[1]} =~ ^[0-9a-f]{64}$ ]] || die 'invalid rollback journal'
  assert_release "${digests[0]}"
  assert_release "${digests[1]}"
  set_pointer "$current" "${digests[0]}"
  set_pointer "$previous" "${digests[1]}"
  rm -- "$journal"
}
validate_release_tree() {
  local allow_missing=$1 release digest entry
  [[ -d $release_root ]] || return 0
  shopt -s nullglob dotglob
  for release in "$release_root"/*; do
    [[ -d $release && ! -L $release ]] || die "unexpected release entry: $release"
    digest=${release##*/}
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || die "unexpected release name: $release"
    check_directory "$release"
    for entry in "$release"/*; do
      [[ $entry == "$release/codex-autoapprover" && -f $entry && ! -L $entry ]] || die "unexpected release contents: $entry"
    done
    if [[ -e $release/codex-autoapprover ]]; then
      assert_release "$digest"
    else
      [[ $allow_missing == yes ]] || die "incomplete release: $digest"
    fi
  done
  shopt -u nullglob dotglob
}
finish_uninstall() {
  [[ -f $uninstall_journal && ! -L $uninstall_journal && $(stat -c %u -- "$uninstall_journal") == "$current_uid" && $(stat -c %h -- "$uninstall_journal") == 1 && $(stat -c %s -- "$uninstall_journal") -le 128 ]] || die 'unsafe uninstall journal'
  [[ $(cat -- "$uninstall_journal") == codex-autoapprover-uninstall-v1 ]] || die 'invalid uninstall journal'
  [[ ( ! -e $current || -L $current ) && ( ! -e $previous || -L $previous ) ]] || die 'unmanaged file appeared during uninstall'
  validate_release_tree yes
  [[ ! -L $current ]] || rm -- "$current"
  [[ ! -L $previous ]] || rm -- "$previous"
  if [[ -d $release_root ]]; then
    shopt -s nullglob
    for release in "$release_root"/*; do
      [[ ! -e $release/codex-autoapprover ]] || rm -- "$release/codex-autoapprover"
      rmdir -- "$release"
    done
    shopt -u nullglob
    rmdir -- "$release_root"
  fi
  [[ ! -e $marker ]] || rm -- "$marker"
  rm -- "$uninstall_journal"
}

if [[ $action == install ]]; then
  [[ $(digest_file "$binary") == "$expected" ]] || die 'artifact digest differs from authenticated expected SHA-256'
fi
if [[ $action != install && ! -e $install_dir && ! -L $install_dir ]]; then
  case "$action" in
    status) printf 'Current: none\nPrevious: none\n'; exit 0 ;;
    uninstall) printf 'Already uninstalled.\n'; exit 0 ;;
    rollback) die 'no managed installation to roll back' ;;
  esac
fi
ensure_directory_chain
release_root="$install_dir/.codex-autoapprover-releases"
current="$install_dir/codex-autoapprover"
previous="$install_dir/.codex-autoapprover-previous"
marker="$install_dir/.codex-autoapprover-owned"
journal="$install_dir/.codex-autoapprover-rollback-journal"
uninstall_journal="$install_dir/.codex-autoapprover-uninstall-journal"
lock="$install_dir/.codex-autoapprover.lock"
[[ ! -L $lock && ( ! -e $lock || ( -f $lock && $(stat -c %u -- "$lock") == "$current_uid" && $(stat -c %h -- "$lock") == 1 ) ) ]] || die 'unsafe install lock'
exec 9>> "$lock"
chmod 600 -- "$lock"
flock -x 9
check_marker
if [[ -e $release_root || -L $release_root ]]; then
  [[ -d $release_root && ! -L $release_root ]] || die 'unsafe release directory'
  check_directory "$release_root"
elif [[ $action == install ]]; then
  mkdir -m 700 -- "$release_root"
fi
if [[ -d $release_root ]]; then cleanup_stages; fi
if [[ -e $uninstall_journal || -L $uninstall_journal ]]; then
  [[ ! -e $journal && ! -L $journal ]] || die 'conflicting recovery journals'
  finish_uninstall
  case "$action" in
    install) check_marker; mkdir -m 700 -- "$release_root" ;;
    rollback) die 'interrupted uninstall completed; no previous release remains' ;;
    status) printf 'Current: none\nPrevious: none\n'; exit 0 ;;
    uninstall) printf 'Recovered interrupted uninstall.\n'; exit 0 ;;
  esac
fi
recover_rollback
old=$(pointer_digest "$current")
prior=$(pointer_digest "$previous")

case "$action" in
  install)
    if [[ $old == "$expected" ]]; then
      timeout 15s "$release_root/$expected/codex-autoapprover" verify-manifest --manifest "$manifest" >/dev/null || die 'installed executable/manifest verification failed'
      timeout 15s "$release_root/$expected/codex-autoapprover" --help >/dev/null || die 'installed executable health check failed'
      printf 'Already installed: %s\n' "$old"
      exit 0
    fi
    stage=$(mktemp -d "$release_root/.stage.XXXXXXXX")
    trap 'if [[ -n ${stage:-} && -d $stage ]]; then rm -f -- "$stage/codex-autoapprover"; rmdir -- "$stage"; fi' EXIT
    cp -- "$binary" "$stage/codex-autoapprover"
    chmod 700 -- "$stage/codex-autoapprover"
    [[ $(digest_file "$stage/codex-autoapprover") == "$expected" ]] || die 'staged artifact digest mismatch'
    timeout 15s "$stage/codex-autoapprover" verify-manifest --manifest "$manifest" >/dev/null || die 'staged executable/manifest verification failed'
    timeout 15s "$stage/codex-autoapprover" --help >/dev/null || die 'staged executable health check failed'
    if [[ -e $release_root/$expected || -L $release_root/$expected ]]; then
      assert_release "$expected"
    else
      mv -T -- "$stage" "$release_root/$expected"
      stage=''
    fi
    if [[ -n $old ]]; then set_pointer "$previous" "$old"; fi
    set_pointer "$current" "$expected"
    printf 'Installed: %s\n' "$expected"
    ;;
  rollback)
    [[ -n $old && -n $prior && $old != "$prior" ]] || die 'no distinct previous release to restore'
    journal_tmp="$install_dir/.codex-autoapprover-journal.$BASHPID.$RANDOM"
    printf '%s\n%s\n' "$prior" "$old" > "$journal_tmp"
    mv -Tf -- "$journal_tmp" "$journal"
    recover_rollback
    printf 'Rolled back to: %s\n' "$prior"
    ;;
  status)
    printf 'Current: %s\nPrevious: %s\n' "${old:-none}" "${prior:-none}"
    ;;
  uninstall)
    validate_release_tree no
    journal_tmp="$install_dir/.codex-autoapprover-uninstall.$BASHPID.$RANDOM"
    printf 'codex-autoapprover-uninstall-v1\n' > "$journal_tmp"
    mv -Tf -- "$journal_tmp" "$uninstall_journal"
    finish_uninstall
    printf 'Uninstalled managed codex-autoapprover releases. Codex configuration was untouched.\n'
    ;;
esac
