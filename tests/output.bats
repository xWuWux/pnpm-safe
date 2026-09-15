#!/usr/bin/env bats
# tests/output.bats — lib/output.sh: audit log emission and directory setup.

load test_helper.bash

teardown() { teardown_isolated_env; }

@test "sourcing output.sh creates the audit log directory even when PNPM_SAFE_CACHE is customized" {
  # Regression: AUDIT_LOG/LOG_FILE default under ~/.cache/pnpm-safe
  # independently of PNPM_SAFE_CACHE (a documented override). Only
  # CACHE_DIR was ever mkdir -p'd by callers, so customizing
  # PNPM_SAFE_CACHE alone left the audit log's directory never created,
  # crashing the first _emit() call under `set -e`.
  export TEST_HOME
  TEST_HOME="$(mktemp -d)"
  export HOME="$TEST_HOME"
  export PNPM_SAFE_CACHE="${TEST_HOME}/somewhere/custom"
  unset PNPM_SAFE_AUDIT_LOG PNPM_SAFE_LOG

  LIB_DIR="${REPO_ROOT}/lib"
  # shellcheck disable=SC1091
  source "${LIB_DIR}/output.sh"

  [ -d "$(dirname "$AUDIT_LOG")" ]
  [ -d "$(dirname "$LOG_FILE")" ]
}

@test "_emit writes a valid JSONL line and does not error" {
  setup_isolated_env
  LIB_DIR="${REPO_ROOT}/lib"
  # shellcheck disable=SC1091
  source "${LIB_DIR}/output.sh"

  _emit "BLOCK" "evil-pkg" "1.0.0" "test reason" "rule_a" "rule_b"
  [ -f "$AUDIT_LOG" ]
  run python3 -c "import json; json.load(open('${AUDIT_LOG}'))" 2>&1
  # python3 -c on a file with one JSON object per line will fail (that's
  # JSONL, not a single JSON doc) — check the *last line* parses instead.
  run python3 -c "
import json
with open('${AUDIT_LOG}') as f:
    line = f.readlines()[-1]
e = json.loads(line)
assert e['level'] == 'BLOCK'
assert e['package'] == 'evil-pkg'
assert e['rules'] == ['rule_a', 'rule_b']
print('OK')
"
  [ "$status" -eq 0 ]
  [[ "$output" == "OK" ]]
}

@test "_json_str escapes quotes, backslashes, and newlines" {
  LIB_DIR="${REPO_ROOT}/lib"
  # shellcheck disable=SC1091
  source "${LIB_DIR}/output.sh"
  result="$(_json_str 'a "quoted" \backslash\ line
break')"
  [[ "$result" == *'\"quoted\"'* ]]
  [[ "$result" == *'\\backslash\\'* ]]
  [[ "$result" == *'\n'* ]]
}
