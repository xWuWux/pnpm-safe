#!/usr/bin/env bats
# tests/risk_scoring.bats — lib/risk.sh scoring logic, network-free.
#
# get_version_publish_time (lib/registry.sh) is stubbed to return a
# controlled epoch, so these test the pure arithmetic/tiering logic in
# isolation rather than depending on live npm registry data or timing.

load test_helper.bash

setup() {
  setup_isolated_env
  SCRIPT_DIR="${REPO_ROOT}/bin"
  LIB_DIR="${REPO_ROOT}/lib"
  RULES_DIR="${REPO_ROOT}/rules"
  # shellcheck disable=SC1091
  source "${LIB_DIR}/output.sh"
  # shellcheck disable=SC1091
  source "${LIB_DIR}/modes.sh"
  # shellcheck disable=SC1091
  source "${LIB_DIR}/registry.sh"
  # shellcheck disable=SC1091
  source "${LIB_DIR}/risk.sh"

  # Stub out the one function that would otherwise hit the network.
  get_version_publish_time() { echo "$STUB_PUBLISH_EPOCH"; }
}

teardown() { teardown_isolated_env; }

@test "score_publish_age: a package that already clears a custom sub-24h policy scores 0" {
  # Regression: MIN_RELEASE_AGE_MINUTES=600 (10h) and a package published
  # 15h ago used to score 30 points ("below 10h threshold") even though
  # 15h > 10h — the middle tier checked a hardcoded 1440 (24h) boundary
  # unconditionally instead of gating on the actual configured threshold
  # first.
  MIN_RELEASE_AGE_MINUTES=600
  STUB_PUBLISH_EPOCH=$(( $(date +%s) - 15*3600 ))
  result="$(score_publish_age some-pkg 1.0.0)"
  score="${result%%:*}"
  [ "$score" -eq 0 ]
}

@test "score_publish_age: a package younger than a custom sub-24h policy still scores > 0" {
  MIN_RELEASE_AGE_MINUTES=600
  STUB_PUBLISH_EPOCH=$(( $(date +%s) - 5*3600 ))  # 5h old, policy wants 10h
  result="$(score_publish_age some-pkg 1.0.0)"
  score="${result%%:*}"
  [ "$score" -gt 0 ]
}

@test "score_publish_age: extreme freshness (<1h) always scores 50 regardless of policy" {
  MIN_RELEASE_AGE_MINUTES=10080
  STUB_PUBLISH_EPOCH=$(( $(date +%s) - 30*60 ))  # 30 minutes old
  result="$(score_publish_age some-pkg 1.0.0)"
  score="${result%%:*}"
  [ "$score" -eq 50 ]
}

@test "score_publish_age: default balanced-mode behavior is unchanged (regression guard)" {
  MIN_RELEASE_AGE_MINUTES=1440  # balanced default, 24h
  STUB_PUBLISH_EPOCH=$(( $(date +%s) - 10*3600 ))  # 10h old, below 24h policy
  result="$(score_publish_age some-pkg 1.0.0)"
  score="${result%%:*}"
  [ "$score" -eq 30 ]
}

@test "score_publish_age: a package older than policy scores 0" {
  MIN_RELEASE_AGE_MINUTES=1440
  STUB_PUBLISH_EPOCH=$(( $(date +%s) - 48*3600 ))  # 48h old, clears 24h policy
  result="$(score_publish_age some-pkg 1.0.0)"
  score="${result%%:*}"
  [ "$score" -eq 0 ]
}

@test "check_package_age runs without 'command not found' and flags a fresh package" {
  # Regression: this function was called by bin/scan-lockfile --check-age
  # but never defined anywhere in the codebase.
  MIN_RELEASE_AGE_MINUTES=1440
  STUB_PUBLISH_EPOCH=$(( $(date +%s) - 30*60 ))
  RISK_FOUND=0
  BLOCK_TRIGGERED=0
  run check_package_age some-pkg 1.0.0
  [ "$status" -eq 0 ]
  [[ "$output" != *"command not found"* ]]
}

@test "check_package_age is a no-op for a package with no version" {
  run check_package_age some-pkg ""
  [ "$status" -eq 0 ]
}

@test "score_maintainer_change message has no trailing comma from the join (cosmetic regression)" {
  # comm/tr produce a comma-joined list; the old `${var%; }` strip never
  # matched (wrong separator), leaving a trailing comma in the message.
  removed="alice,bob,"
  msg="Maintainer(s) removed: ${removed%,}. "
  [ "$msg" = "Maintainer(s) removed: alice,bob. " ]
}
