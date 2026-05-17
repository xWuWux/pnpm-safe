#!/usr/bin/env bash
# lib/output.sh — terminal output + structured JSONL audit logging
#
# Two parallel streams:
#   1. Colored stderr for interactive use
#   2. JSONL audit log for incident response / SIEM ingestion
#
# Audit event schema:
#   { "ts", "session", "mode", "level", "package", "version",
#     "reason", "rules", "cwd", "git_ref", "cmd" }

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}${*}${RESET}" >&2; }
warn()    { echo -e "${YELLOW}${BOLD}${*}${RESET}" >&2; }
error()   { echo -e "${RED}${BOLD}${*}${RESET}" >&2; }
success() { echo -e "${GREEN}${*}${RESET}" >&2; }

# Stable session ID for correlating all events from one pnpm-safe invocation
SESSION_ID="${PNPM_SAFE_SESSION:-$(date +%s%N 2>/dev/null | sha256sum 2>/dev/null | head -c 12 || date +%s)}"
AUDIT_LOG="${PNPM_SAFE_AUDIT_LOG:-${HOME}/.cache/pnpm-safe/audit.jsonl}"
LOG_FILE="${PNPM_SAFE_LOG:-${HOME}/.cache/pnpm-safe/run.log}"

_json_str() {
  # Minimal safe JSON string escaping
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"
  echo "$s"
}

_git_ref() { git rev-parse --short HEAD 2>/dev/null || true; }

# Core structured event emitter — all other log functions call this
_emit() {
  local level="$1" pkg="$2" version="$3" reason="$4"
  shift 4
  local rules_json="[]"
  if [[ $# -gt 0 ]]; then
    local joined; joined=$(printf '"%s",' "$@"); rules_json="[${joined%,}]"
  fi
  local ts; ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  printf '{"ts":"%s","session":"%s","mode":"%s","level":"%s","package":"%s","version":"%s","reason":"%s","rules":%s,"cwd":"%s","git_ref":"%s","cmd":"%s"}\n' \
    "$ts" "$SESSION_ID" "${ACTIVE_MODE:-unset}" "$level" \
    "$(_json_str "$pkg")" "$(_json_str "$version")" "$(_json_str "$reason")" \
    "$rules_json" \
    "$(_json_str "$PWD")" "$(_git_ref)" "$(_json_str "${PNPM_SAFE_CMD:-}")" \
    >> "$AUDIT_LOG"
  # Mirror to text log for grep-ability
  echo "[${ts}] ${level} ${pkg}${version:+@${version}} — ${reason}" >> "$LOG_FILE"
}

log_event() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] ${*}" >> "$LOG_FILE"; }

# flag_risk LEVEL PKG REASON [RULE_TAG...]
flag_risk() {
  local level="$1" pkg="$2" reason="$3"; shift 3
  RISK_FOUND=$((RISK_FOUND + 1))
  _emit "$level" "$pkg" "" "$reason" "$@"
  if [[ "$level" == "BLOCK" ]]; then
    BLOCK_TRIGGERED=$((BLOCK_TRIGGERED + 1))
    error "  [BLOCK] ${pkg}: ${reason}"
  else
    warn "  [WARN]  ${pkg}: ${reason}"
  fi
}

# flag_risk_v LEVEL PKG VERSION REASON [RULE_TAG...]
flag_risk_v() {
  local level="$1" pkg="$2" version="$3" reason="$4"; shift 4
  RISK_FOUND=$((RISK_FOUND + 1))
  _emit "$level" "$pkg" "$version" "$reason" "$@"
  if [[ "$level" == "BLOCK" ]]; then
    BLOCK_TRIGGERED=$((BLOCK_TRIGGERED + 1))
    error "  [BLOCK] ${pkg}@${version}: ${reason}"
  else
    warn "  [WARN]  ${pkg}@${version}: ${reason}"
  fi
}

log_allow()      { _emit "ALLOW" "$1" "${2:-}" "passed all checks"; }
log_clean_scan() { _emit "CLEAN" "$1" ""       "no IOCs detected";  }

show_audit_tail() {
  local n="${1:-20}"
  [[ ! -f "$AUDIT_LOG" ]] && { info "No audit log at ${AUDIT_LOG}"; return; }
  echo ""
  printf "Last %s audit events — %s\n" "$n" "$AUDIT_LOG"
  echo "────────────────────────────────────────────────────────────────────"
  tail -n "$n" "$AUDIT_LOG" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        lvl = e.get('level','?'); pkg = e.get('package','?')
        ver = e.get('version',''); ts = e.get('ts','')[:19]
        rsn = e.get('reason','')[:55]
        print(f'{ts}  {lvl:<6}  {pkg+(\"@\"+ver if ver else \"\"):<42}  {rsn}')
    except Exception:
        print(line.rstrip())
"
  echo "────────────────────────────────────────────────────────────────────"
}
