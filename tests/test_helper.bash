# tests/test_helper.bash — shared setup for all .bats files
#
# Every test gets an isolated HOME/cache dir so nothing here ever touches
# the real ~/.cache/pnpm-safe, and no test depends on network access
# (registry-dependent functions are stubbed — see individual test files).

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

setup_isolated_env() {
  export TEST_HOME
  TEST_HOME="$(mktemp -d)"
  export HOME="$TEST_HOME"
  export PNPM_SAFE_CACHE="${TEST_HOME}/.cache/pnpm-safe"
  export PNPM_SAFE_AUDIT_LOG="${PNPM_SAFE_CACHE}/audit.jsonl"
  export PNPM_SAFE_LOG="${PNPM_SAFE_CACHE}/run.log"
  mkdir -p "$PNPM_SAFE_CACHE"
}

teardown_isolated_env() {
  # `[[ ... ]] && cmd` as the last statement in a function makes the
  # function itself fail whenever the condition is false (there's
  # nothing to clean up, e.g. a test that never called
  # setup_isolated_env) — bats treats a non-zero teardown as a failure
  # even when the test body passed. `|| true` keeps this a no-op.
  [[ -n "${TEST_HOME:-}" && -d "$TEST_HOME" ]] && rm -rf "$TEST_HOME"
  true
}

# A fake `pnpm` on PATH, so tests never need the real thing installed and
# never actually touch a project's dependencies. Prints its argv and exits
# 0 unless FAKE_PNPM_EXIT is set.
install_fake_pnpm() {
  export FAKE_PNPM_DIR
  FAKE_PNPM_DIR="$(mktemp -d)"
  cat > "${FAKE_PNPM_DIR}/pnpm" <<'EOF'
#!/bin/bash
echo "[fake pnpm] $*"
exit "${FAKE_PNPM_EXIT:-0}"
EOF
  chmod +x "${FAKE_PNPM_DIR}/pnpm"
  export PATH="${FAKE_PNPM_DIR}:${PATH}"
}

uninstall_fake_pnpm() {
  [[ -n "${FAKE_PNPM_DIR:-}" && -d "$FAKE_PNPM_DIR" ]] && rm -rf "$FAKE_PNPM_DIR"
}
