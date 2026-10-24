#!/usr/bin/env bash
# secops-guard machine setup: package-manager cooldown configs + Claude Code settings.
#
# DRY RUN BY DEFAULT. Prints every change it would make and exits. Pass --apply to write.
# Never needs root. Never touches managed-settings.json. Backs up every file it writes.
#
#   bash setup/install.sh
#   bash setup/install.sh --apply
#   bash setup/install.sh --apply --cooldown-days 14 --skip-ignore-scripts
#   bash setup/install.sh --uninstall --apply
#   bash setup/install.sh --uninstall --restore-backups --apply   # full rollback
#
# Kept bash 3.2 compatible so it runs on a stock macOS shell: no mapfile, no `declare -A`.

set -uo pipefail

APPLY=0
COOLDOWN_DAYS=7
SKIP_IGNORE_SCRIPTS=0
NO_PLUGIN_INSTALL=0
NO_DENY_RULES=0
UNINSTALL=0
RESTORE_BACKUPS=0
QUIET=0

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --dry-run) APPLY=0 ;;
    --cooldown-days) COOLDOWN_DAYS="${2:-}"; shift ;;
    --skip-ignore-scripts) SKIP_IGNORE_SCRIPTS=1 ;;
    --no-plugin-install) NO_PLUGIN_INSTALL=1 ;;
    --no-deny-rules) NO_DENY_RULES=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --restore-backups) RESTORE_BACKUPS=1 ;;
    --quiet) QUIET=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "secops-guard: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

case "$COOLDOWN_DAYS" in
  ''|*[!0-9]*) echo "secops-guard: --cooldown-days must be a whole number" >&2; exit 2 ;;
esac

SETUP_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SETUP_DIR")"
CONFIG_DIR="$SETUP_DIR/configs"
CLAUDE_HOME="$HOME/.claude"
STAMP="$(date +%Y%m%d%H%M%S)"
COOLDOWN_MINUTES=$((COOLDOWN_DAYS * 1440))
COOLDOWN_SECONDS=$((COOLDOWN_DAYS * 86400))

APPLIED=""; SKIPPED=""; FAILED=""; FAIL_COUNT=0

say()  { [ "$QUIET" = 1 ] || printf '%s\n' "$*"; }
head_() { [ "$QUIET" = 1 ] || printf '\n%s\n' "$*"; }
warn() { printf '  ! %s\n' "$*" >&2; }
record() { # record APPLIED|SKIPPED|FAILED <text>
  case "$1" in
    APPLIED) APPLIED="${APPLIED}$2"$'\n' ;;
    SKIPPED) SKIPPED="${SKIPPED}$2"$'\n' ;;
    FAILED)  FAILED="${FAILED}$2"$'\n' ;;
  esac
}

# ---------------------------------------------------------------- tool versions

tool_version() { # tool_version <exe> [args...]
  local exe="$1"; shift
  command -v "$exe" >/dev/null 2>&1 || return 1
  # Two components are enough: pip reports "pip 26.1", so requiring three never matched it
  # and the pip cooldown was silently skipped as "not installed".
  "$exe" "$@" 2>&1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1
}

ver_ge() { # ver_ge <have> <min>
  [ -n "$1" ] || return 1
  awk -v a="$1" -v b="$2" 'BEGIN{
    na=split(a,x,"."); nb=split(b,y,".");
    n = (na>nb?na:nb);
    for(i=1;i<=n;i++){ xi=(i<=na?x[i]+0:0); yi=(i<=nb?y[i]+0:0);
      if(xi>yi) exit 0; if(xi<yi) exit 1 }
    exit 0 }'
}

# ------------------------------------------------------------------ file helpers

backup_file() {
  [ -f "$1" ] || return 0
  # Never clobber an existing backup: two runs inside the same second would
  # otherwise destroy the original copy.
  local b="$1.secops-bak-$STAMP" n=1
  while [ -e "$b" ]; do n=$((n + 1)); b="$1.secops-bak-$STAMP-$n"; done
  # A failed backup must stop the write, not be ignored: the caller overwrote the target
  # anyway, so a read-only directory destroyed the original with no copy to restore.
  cp "$1" "$b" || { say "  ERROR: could not back up $1 - not writing it"; return 1; }
  say "  backup: $b"
  say "  restore with: cp \"$b\" \"$1\""
}

newest_backup() {
  ls -1 "$1".secops-bak-* 2>/dev/null | sort | tail -1
}

# Full rollback to the oldest state this installer ever saw. Only with
# --uninstall --restore-backups, because it also reverts edits you made since.
restore_backup() {
  local target="$1" oldest
  oldest="$(ls -1 "$target".secops-bak-* 2>/dev/null | sort | head -1)"
  if [ -z "$oldest" ]; then say "  no backup to restore for $target"; return 1; fi
  say "--- $target"
  say "+++ $oldest  (full restore - DISCARDS every change made since)"
  if [ "$APPLY" = 1 ]; then
    backup_file "$target" || return 1
    cp "$oldest" "$target"
    say "  restored $target from $oldest"
  fi
  return 0
}

# ------------------------------------------------------------- snippet handling

# Emits "<section>\t<key>\t<line>" per setting. Comments are documentation only.
read_snippet() {
  local file="$CONFIG_DIR/$1"
  [ -f "$file" ] || { echo "secops-guard: missing snippet $file" >&2; return 1; }
  awk -v days="$COOLDOWN_DAYS" -v mins="$COOLDOWN_MINUTES" -v secs="$COOLDOWN_SECONDS" '
    { sub(/\r$/, "") ; line=$0
      gsub(/^[ \t]+|[ \t]+$/, "", line)
      if (line == "" || line ~ /^#/) next
      if (line ~ /^\[.*\]$/) { section = substr(line, 2, length(line)-2); next }
      gsub(/@DAYS@/, days, line); gsub(/@MINUTES@/, mins, line); gsub(/@SECONDS@/, secs, line)
      p = index(line, "="); q = index(line, ":")
      if (p == 0 || (q > 0 && q < p)) p = q
      if (p < 2) { print "PARSE_ERROR " line > "/dev/stderr"; exit 3 }
      key = substr(line, 1, p-1); gsub(/[ \t]+$/, "", key)
      printf "%s\037%s\037%s\n", section, key, line
    }' "$file"
}

# Upserts every snippet key into $1. Echoes the diff; writes only with --apply.
merge_snippet() {
  local target="$1" snippet="$2"
  local -a lines=()
  local existed=0
  if [ -f "$target" ]; then
    existed=1
    while IFS= read -r l || [ -n "$l" ]; do lines+=("${l%$'\r'}"); done < "$target"
  fi

  local diff="" entry section key line i start end hdr found n
  while IFS=$'\037' read -r section key line; do
    [ -n "$key" ] || continue
    n=${#lines[@]}
    start=0; end=$n

    if [ -n "$section" ]; then
      hdr=-1
      for ((i = 0; i < n; i++)); do
        case "$(printf '%s' "${lines[$i]}" | tr -d ' \t')" in
          "[$section]") hdr=$i; break ;;
        esac
      done
      if [ "$hdr" -lt 0 ]; then
        if [ "$n" -gt 0 ] && [ -n "${lines[$((n-1))]// /}" ]; then lines+=(""); fi
        lines+=("[$section]")
        diff="$diff"$'\n'"+[$section]"
        n=${#lines[@]}; hdr=$((n-1))
      fi
      start=$((hdr + 1)); end=${#lines[@]}
      for ((i = start; i < ${#lines[@]}; i++)); do
        case "${lines[$i]}" in \[*) end=$i; break ;; esac
      done
    fi

    local esc; esc="$(printf '%s' "$key" | sed 's/[][\.*^$\/+?(){}|]/\\&/g')"
    found=-1
    for ((i = start; i < end; i++)); do
      if printf '%s' "${lines[$i]}" | grep -qE "^[[:space:]]*$esc[[:space:]]*[:=]"; then
        found=$i; break
      fi
    done

    if [ "$found" -ge 0 ]; then
      local cur="${lines[$found]}"
      cur="$(printf '%s' "$cur" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
      [ "$cur" = "$line" ] && continue          # already correct - idempotent
      diff="$diff"$'\n'"-${lines[$found]}"$'\n'"+$line"
      lines[$found]="$line"
    else
      local at
      if [ -n "$section" ]; then at=$end; else
        at=0
        while [ "$at" -lt "${#lines[@]}" ]; do
          case "$(printf '%s' "${lines[$at]}" | sed 's/^[[:space:]]*//')" in
            ''|'#'*|';'*) at=$((at + 1)) ;;
            *) break ;;
          esac
        done
      fi
      local -a rebuilt=()
      for ((i = 0; i < ${#lines[@]}; i++)); do
        [ "$i" = "$at" ] && rebuilt+=("$line")
        rebuilt+=("${lines[$i]}")
      done
      [ "$at" -ge "${#lines[@]}" ] && rebuilt+=("$line")
      lines=("${rebuilt[@]}")
      diff="$diff"$'\n'"+$line"
    fi
  done < <(read_snippet "$snippet")

  [ -n "$diff" ] || return 1
  [ "$existed" = 1 ] && say "--- $target" || say "--- $target  (new file)"
  say "+++ $target  (secops-guard)"
  printf '%s\n' "$diff" | sed '/^$/d; s/^/  /'
  if [ "$APPLY" = 1 ]; then
    backup_file "$target" || return 1
    mkdir -p "$(dirname "$target")"
    printf '%s\n' "${lines[@]}" > "$target"
    say "  wrote $target"
  fi
  return 0
}

# Deletes exactly the keys this installer writes. Surgical on purpose: restoring a
# backup wholesale would also revert unrelated edits made since.
remove_snippet() {
  local target="$1" snippet="$2"
  [ -f "$target" ] || return 1
  local tmp diff="" section key line
  tmp="$(mktemp)"
  cp "$target" "$tmp"
  while IFS=$'\037' read -r section key line; do
    [ -n "$key" ] || continue
    local esc; esc="$(printf '%s' "$key" | sed 's/[][\.*^$\/+?(){}|]/\\&/g')"
    local hits; hits="$(grep -nE "^[[:space:]]*$esc[[:space:]]*[:=]" "$tmp" || true)"
    [ -n "$hits" ] || continue
    diff="$diff"$'\n'"$(printf '%s' "$hits" | sed 's/^[0-9]*:/-/')"
    grep -vE "^[[:space:]]*$esc[[:space:]]*[:=]" "$tmp" > "$tmp.new" && mv "$tmp.new" "$tmp"
  done < <(read_snippet "$snippet")

  if [ -z "$diff" ]; then rm -f "$tmp"; return 1; fi
  say "--- $target"
  say "+++ $target  (secops-guard uninstall)"
  printf '%s\n' "$diff" | sed '/^$/d; s/^/  /'
  local bak; bak="$(newest_backup "$target")"
  [ -n "$bak" ] && { say "  newest backup kept: $bak"; say "  full restore: cp \"$bak\" \"$target\""; }
  if [ "$APPLY" = 1 ]; then
    backup_file "$target" || return 1
    cp "$tmp" "$target"
    say "  wrote $target"
  fi
  rm -f "$tmp"
  return 0
}

# ------------------------------------------------------------------ the matrix

NPM_V="$(tool_version npm -v || true)"
PNPM_V="$(tool_version pnpm -v || true)"
UV_V="$(tool_version uv --version || true)"
PIP_V="$(tool_version pip --version || tool_version pip3 --version || true)"
CARGO_V="$(tool_version cargo --version || true)"
YARN_V="$(tool_version yarn -v || true)"
BUN_V="$(tool_version bun -v || true)"
NODE_V="$(tool_version node -v || true)"

case "$(uname -s)" in
  Darwin) PNPM_TARGET="$HOME/Library/Preferences/pnpm/config.yaml" ;;
  *)      PNPM_TARGET="${XDG_CONFIG_HOME:-$HOME/.config}/pnpm/config.yaml" ;;
esac

# id|tool|have|min|snippet|target|upgrade|note
MATRIX="
npm-cooldown|npm|$NPM_V|11.10.0|npm.npmrc|$HOME/.npmrc|npm i -g npm@latest|min-release-age (days)
npm-no-scripts|npm|$NPM_V|0.0.0|npm-ignore-scripts.npmrc|$HOME/.npmrc||ignore-scripts (blocks preinstall worms)
pnpm-cooldown|pnpm|$PNPM_V|10.16.0|pnpm-config.yaml|$PNPM_TARGET|npm i -g pnpm@latest|minimumReleaseAge (minutes)
uv-cooldown|uv|$UV_V|0.9.17|uv.toml|${XDG_CONFIG_HOME:-$HOME/.config}/uv/uv.toml|uv self update|exclude-newer (relative duration)
pip-cooldown|pip|$PIP_V|26.1.0|pip.ini|${XDG_CONFIG_HOME:-$HOME/.config}/pip/pip.conf|python3 -m pip install --upgrade pip|uploaded-prior-to (P<n>D)
cargo-cooldown|cargo|$CARGO_V|1.100.0|cargo-config.toml|$HOME/.cargo/config.toml|rustup update (Rust 1.100, due 2026-11-12); until then: cargo install cargo-cooldown|global-min-publish-age
yarn-cooldown|yarn|$YARN_V|4.10.0|yarnrc.yml|$HOME/.yarnrc.yml|corepack enable \&\& yarn set version stable|npmMinimalAgeGate (unit UNVERIFIED)
bun-cooldown|bun|$BUN_V|1.3.0|bunfig.toml|$HOME/.bunfig.toml|bun upgrade|minimumReleaseAge (seconds)
"

# ------------------------------------------------------------------------ run

MODE="DRY RUN (nothing will be written)"
[ "$APPLY" = 1 ] && MODE="APPLY"
[ "$UNINSTALL" = 1 ] && MODE="UNINSTALL"

say ""
say "secops-guard setup  -  cooldown $COOLDOWN_DAYS day(s)  -  $MODE"
say "repo: $REPO_ROOT"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    warn "this is a Windows shell: the config paths below are the POSIX ones."
    warn "for a native Windows install run:  pwsh -File setup/install.ps1 -Apply"
    ;;
esac

head_ "(a) preflight - detected versions and support matrix"
if [ "$QUIET" != 1 ]; then
  printf '  %-16s %-7s %-12s %-10s %s\n' SETTING TOOL INSTALLED REQUIRES STATUS
  printf '%s\n' "$MATRIX" | while IFS='|' read -r id tool have min snippet target upgrade note; do
    [ -n "$id" ] || continue
    if [ -z "$have" ]; then status="not installed"
    elif [ "$id" = npm-no-scripts ] && [ "$SKIP_IGNORE_SCRIPTS" = 1 ]; then status="opted out"
    elif ver_ge "$have" "$min"; then status="supported"
    else status="needs >= $min"; fi
    [ "$min" = "0.0.0" ] && min="any"
    printf '  %-16s %-7s %-12s %-10s %s\n' "$id" "$tool" "${have:--}" "$min" "$status"
  done
  printf '  node %s  (required by the plugin hooks)\n' "${NODE_V:-MISSING}"
fi

head_ "(b) package-manager configs"
while IFS='|' read -r id tool have min snippet target upgrade note; do
  [ -n "$id" ] || continue
  if [ -z "$have" ]; then record SKIPPED "$id: $tool is not installed"; continue; fi
  # yarn: the unit of npmMinimalAgeGate is disputed. Writing the wrong form could
  # make `yarn install` fail, so it is printed as a manual suggestion, never written.
  if [ "$id" = yarn-cooldown ]; then
    warn "yarn-cooldown: NOT written - the npmMinimalAgeGate unit is unverified. Add this to $target by hand if you want it:"
    read_snippet "$snippet" | cut -d"$(printf '\037')" -f3 | sed 's/^/      /'
    say "      then check it with: yarn config get npmMinimalAgeGate"
    record SKIPPED "yarn-cooldown: unit unverified - printed as a manual suggestion instead"
    continue
  fi
  if [ "$id" = npm-no-scripts ] && [ "$SKIP_IGNORE_SCRIPTS" = 1 ]; then
    record SKIPPED "$id: opted out with --skip-ignore-scripts"; continue
  fi
  if ! ver_ge "$have" "$min"; then
    warn "$id: $tool $have is older than $min - key NOT written. Upgrade: $upgrade"
    record SKIPPED "$id: $tool $have < $min - upgrade with: $upgrade"
    continue
  fi
  if [ "$UNINSTALL" = 1 ] && [ "$RESTORE_BACKUPS" = 1 ]; then
    restore_backup "$target" && record APPLIED "restored $target"
  elif [ "$UNINSTALL" = 1 ]; then
    if remove_snippet "$target" "$snippet"; then record APPLIED "$id -> $target"
    else say "  nothing to remove: $id ($target)"; fi
  else
    if merge_snippet "$target" "$snippet"; then record APPLIED "$id -> $target"
    else say "  already correct: $id ($target)"; fi
  fi
done <<EOF
$MATRIX
EOF

head_ "(c) Claude Code settings merge"
SETTINGS="$CLAUDE_HOME/settings.json"
SNIPPET="$SETUP_DIR/settings.snippet.json"

invoke_merge() { # invoke_merge [extra args...]
  if ! command -v node >/dev/null 2>&1; then
    warn "node is not on PATH - cannot touch settings.json. Install Node 18+ and re-run."
    record FAILED "settings.json merge: node not found"; FAIL_COUNT=$((FAIL_COUNT + 1))
    return 1
  fi
  local -a a=("$SETUP_DIR/merge-settings.js" "$SETTINGS" "$SNIPPET")
  [ "$APPLY" = 1 ] && a+=(--apply)
  [ "$UNINSTALL" = 1 ] && a+=(--remove)
  [ "$NO_DENY_RULES" = 1 ] && a+=(--no-snippet)
  a+=("$@")
  if node "${a[@]}" 2>&1 | sed 's/^/  /'; then
    record APPLIED "settings.json merged ($SETTINGS)"
  else
    warn "settings.json merge FAILED"
    record FAILED "settings.json merge failed"; FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

if [ "$UNINSTALL" = 1 ] && [ "$RESTORE_BACKUPS" = 1 ]; then
  restore_backup "$SETTINGS" && record APPLIED "restored $SETTINGS"
elif [ "$NO_DENY_RULES" = 1 ]; then
  say "  --no-deny-rules: skipping the permission deny rules. The guard.js hook still covers"
  say "  these paths; the rules are the backstop for when hooks are off. See $SNIPPET"
  record SKIPPED "permission deny rules: declined with --no-deny-rules"
else
  invoke_merge
  record APPLIED "permission deny rules (decline them with --no-deny-rules)"
fi

head_ "(d) marketplace + plugin registration"
if [ "$UNINSTALL" = 1 ]; then
  say "  leaving the plugin registered. Remove it yourself with:"
  say "    claude plugin uninstall secops-guard@secops-guard"
else
  say "    claude plugin marketplace add \"$REPO_ROOT\""
  say "    claude plugin install secops-guard@secops-guard"
  if [ "$NO_PLUGIN_INSTALL" = 1 ]; then
    say "  --no-plugin-install: run the two commands above yourself."
  elif ! command -v claude >/dev/null 2>&1; then
    warn "the 'claude' CLI is not on PATH - writing the settings.json entries instead"
    invoke_merge --enable secops-guard@secops-guard --marketplace "secops-guard=$REPO_ROOT"
  elif [ "$APPLY" = 1 ]; then
    if claude plugin marketplace add "$REPO_ROOT" 2>&1 | sed 's/^/    /' &&
       claude plugin install secops-guard@secops-guard 2>&1 | sed 's/^/    /'; then
      record APPLIED "plugin registered via the claude CLI"
    else
      warn "the claude CLI failed - falling back to settings.json entries"
      invoke_merge --enable secops-guard@secops-guard --marketplace "secops-guard=$REPO_ROOT"
    fi
  fi
fi

head_ "(e) optional scanners (nothing is installed for you)"
case "$(uname -s)" in
  Darwin)
    say "    brew install osv-scanner grype syft semgrep gitleaks"
    ;;
  *)
    say "    go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest   # or the release binary"
    say "    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
    say "    uv tool install semgrep"
    ;;
esac
say "    docker scout cves <image>            # bundled with Docker Desktop >= 4.17"
say "    full matrix, caveats and the Trivy malware warning: $SETUP_DIR/tools.md"

head_ "(f) summary"
count() { if [ -z "$1" ]; then echo 0; else printf '%s' "$1" | grep -c . ; fi ; }
say "  applied:  $(count "$APPLIED")"
[ -n "$APPLIED" ] && printf '%s' "$APPLIED" | sed 's/^/    + /'
say "  skipped:  $(count "$SKIPPED")"
[ -n "$SKIPPED" ] && printf '%s' "$SKIPPED" | sed 's/^/    - /'
say "  failed:   $(count "$FAILED")"
[ -n "$FAILED" ] && printf '%s' "$FAILED" | sed 's/^/    x /'
[ "$APPLY" = 1 ] || { say ""; say "  DRY RUN - nothing was written. Re-run with --apply to make these changes."; }
say ""
say "  verify afterwards with: node \"$SETUP_DIR/verify.js\""
say ""

[ "$FAIL_COUNT" -gt 0 ] && exit 1
exit 0
