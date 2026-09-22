#!/usr/bin/env bats
# tests/cli_parsing.bats — bin/pnpm-safe's own argument parsing
#
# Covers a regression that used to make the exact command in this
# project's own README perform zero security scanning: `--mode <value>`
# as two separate tokens (rather than `--mode=<value>`) leaked the value
# token into the pass-through args for `pnpm`, which made
# is_mutating_cmd() fail to recognize the real subcommand and skip the
# entire Phase A-D scan pipeline.

load test_helper.bash

setup() {
  setup_isolated_env
  install_fake_pnpm
}

teardown() {
  uninstall_fake_pnpm
  teardown_isolated_env
}

@test "two-arg --mode form still runs the scan pipeline and execs the real subcommand" {
  cd "$TEST_HOME"
  run bash "${REPO_ROOT}/bin/pnpm-safe" --mode paranoid add lodash
  [ "$status" -eq 0 ]
  [[ "$output" == *"Mode: paranoid"* ]]
  # The scan pipeline must actually run...
  [[ "$output" == *"Phase A"* ]]
  [[ "$output" == *"Phase B"* ]]
  # ...and pnpm must be invoked with "add lodash", never with "paranoid"
  # leaked in as a bogus leading argument.
  [[ "$output" == *"[fake pnpm] add lodash"* ]]
  [[ "$output" != *"[fake pnpm] paranoid"* ]]
}

@test "equals-form --mode=value still works (regression guard against breaking it while fixing the two-arg form)" {
  cd "$TEST_HOME"
  run bash "${REPO_ROOT}/bin/pnpm-safe" --mode=paranoid add lodash
  [ "$status" -eq 0 ]
  [[ "$output" == *"Mode: paranoid"* ]]
  [[ "$output" == *"[fake pnpm] add lodash"* ]]
}

@test "non-mutating pnpm subcommands are still passed through directly, mode value not leaked" {
  cd "$TEST_HOME"
  run bash "${REPO_ROOT}/bin/pnpm-safe" --mode ci list
  [ "$status" -eq 0 ]
  [[ "$output" == *"[fake pnpm] list"* ]]
  [[ "$output" != *"[fake pnpm] ci list"* ]]
}

@test "--audit-tail with a following number sets the tail count" {
  mkdir -p "$(dirname "$PNPM_SAFE_AUDIT_LOG")"
  printf '{"ts":"2026-01-01T00:00:00Z","session":"a","mode":"ci","level":"BLOCK","package":"evil","version":"1.0.0","reason":"x","rules":[],"cwd":"/","git_ref":"","cmd":""}\n' > "$PNPM_SAFE_AUDIT_LOG"
  run bash "${REPO_ROOT}/bin/pnpm-safe" --audit-tail 30
  [ "$status" -eq 0 ]
  [[ "$output" == *"Last 30 audit events"* ]]
}

@test "--audit-tail with no following number falls back to the default (20), doesn't eat the next flag" {
  mkdir -p "$(dirname "$PNPM_SAFE_AUDIT_LOG")"
  : > "$PNPM_SAFE_AUDIT_LOG"
  run bash "${REPO_ROOT}/bin/pnpm-safe" --audit-tail
  [ "$status" -eq 0 ]
  [[ "$output" == *"Last 20 audit events"* ]]
}

@test "--list-modes exits before touching pnpm at all" {
  run bash "${REPO_ROOT}/bin/pnpm-safe" --list-modes
  [ "$status" -eq 0 ]
  [[ "$output" == *"balanced"* ]]
  [[ "$output" == *"paranoid"* ]]
}
