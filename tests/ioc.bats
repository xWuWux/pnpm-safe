#!/usr/bin/env bats
# tests/ioc.bats — lib/ioc.sh: lockfile IOC pattern matching, no network.

load test_helper.bash

setup() {
  setup_isolated_env
  LIB_DIR="${REPO_ROOT}/lib"
  # shellcheck disable=SC1091
  source "${LIB_DIR}/output.sh"
  # shellcheck disable=SC1091
  source "${LIB_DIR}/ioc.sh"
  RISK_FOUND=0
  BLOCK_TRIGGERED=0
}

teardown() { teardown_isolated_env; }

@test "flags the known-malicious TanStack commit hash as BLOCK" {
  cat > "${TEST_HOME}/lock.yaml" <<'EOF'
packages:
  /some-pkg/1.0.0:
    dependencies:
      evil-dep: "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
EOF
  run scan_lockfile_iocs "${TEST_HOME}/lock.yaml"
  [[ "$output" == *"KNOWN MALICIOUS commit hash"* ]]
  [[ "$output" == *"[BLOCK]"* ]]
}

@test "flags an unknown github: optionalDep as WARN (exotic source), not BLOCK" {
  cat > "${TEST_HOME}/lock.yaml" <<'EOF'
packages:
  /some-pkg/1.0.0:
    dependencies:
      other-dep: "github:someorg/somerepo#deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
EOF
  run scan_lockfile_iocs "${TEST_HOME}/lock.yaml"
  [[ "$output" == *"exotic source"* ]]
  [[ "$output" == *"[WARN]"* ]]
  [[ "$output" != *"[BLOCK]"* ]]
}

@test "a clean lockfile produces no findings and returns success" {
  cat > "${TEST_HOME}/lock.yaml" <<'EOF'
packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-xxx}
EOF
  run scan_lockfile_iocs "${TEST_HOME}/lock.yaml"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "flags a known malicious payload filename referenced in the lockfile" {
  cat > "${TEST_HOME}/lock.yaml" <<'EOF'
packages:
  /some-pkg/1.0.0:
    resolution: {tarball: https://example.com/router_init.js}
EOF
  run scan_lockfile_iocs "${TEST_HOME}/lock.yaml"
  [[ "$output" == *"Known malicious payload filename"* ]]
  [[ "$output" == *"[BLOCK]"* ]]
}

@test "flags a campaign IOC string anywhere in the lockfile" {
  cat > "${TEST_HOME}/lock.yaml" <<'EOF'
packages:
  /some-pkg/1.0.0:
    # __DAEMONIZED
    resolution: {integrity: sha512-xxx}
EOF
  run scan_lockfile_iocs "${TEST_HOME}/lock.yaml"
  [[ "$output" == *"Campaign IOC string"* ]]
}

@test "check_persistence_after_install detects a dead-man's-switch file" {
  dm="${TEST_HOME}/.config/systemd/user/gh-token-monitor.service"
  mkdir -p "$(dirname "$dm")"
  echo "fake unit" > "$dm"
  run check_persistence_after_install
  [ "$status" -eq 1 ]
  [[ "$output" == *"Do NOT revoke GitHub tokens"* ]]
}

@test "check_persistence_after_install is clean when nothing is present" {
  run check_persistence_after_install
  [ "$status" -eq 0 ]
}
