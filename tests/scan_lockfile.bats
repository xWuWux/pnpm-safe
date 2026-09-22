#!/usr/bin/env bats
# tests/scan_lockfile.bats — bin/scan-lockfile, the standalone/CI entry point
#
# This file's job is mostly regression coverage for bugs that made the
# whole script fail to run at all under `set -euo pipefail`: two globals
# (RULES_DIR, CACHE_TTL) that lib/risk.sh and lib/registry.sh reference
# unconditionally were set in bin/pnpm-safe but never in bin/scan-lockfile,
# so `set -u` killed it before Phase 1 ever ran — on every invocation,
# clean lockfile or not. Separately, scan_lockfile_iocs() returns 1 the
# moment it finds anything, which under `set -e` used to abort the script
# immediately (skipping Phase 2/3 and the summary/exit-code logic)
# instead of being treated as "a finding was recorded, keep going."

load test_helper.bash

setup() { setup_isolated_env; }
teardown() { teardown_isolated_env; }

write_clean_lockfile() {
  cat > "${TEST_HOME}/clean-lock.yaml" <<'EOF'
packages: {}
EOF
}

write_ioc_lockfile() {
  cat > "${TEST_HOME}/ioc-lock.yaml" <<'EOF'
packages:
  /some-pkg/1.0.0:
    dependencies:
      evil-dep: "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
EOF
}

write_warn_only_lockfile() {
  cat > "${TEST_HOME}/warn-lock.yaml" <<'EOF'
packages:
  /some-pkg/1.0.0:
    dependencies:
      other-dep: "github:someorg/somerepo#deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
EOF
}

@test "runs to completion (does not crash) on a clean lockfile, default env" {
  write_clean_lockfile
  run bash "${REPO_ROOT}/bin/scan-lockfile" "${TEST_HOME}/clean-lock.yaml"
  [ "$status" -eq 0 ]
  [[ "$output" == *"RESULT: No known IOCs detected"* ]]
  # Must reach the summary section — a crash mid-script would exit
  # without ever printing this.
  [[ "$output" == *"─────"* ]]
}

@test "still runs Phase 2/3 and prints the BLOCK summary when a known-malicious IOC is found (was: silent set -e abort)" {
  write_ioc_lockfile
  run bash "${REPO_ROOT}/bin/scan-lockfile" "${TEST_HOME}/ioc-lock.yaml"
  [ "$status" -eq 1 ]
  [[ "$output" == *"KNOWN MALICIOUS commit hash"* ]]
  [[ "$output" == *"Phase 3"* ]]
  [[ "$output" == *"RESULT:"* ]]
  [[ "$output" == *"Do not install"* ]]
}

@test "exit code is 2 (warn-only), not 1, when nothing BLOCK-level was found" {
  write_warn_only_lockfile
  run bash "${REPO_ROOT}/bin/scan-lockfile" "${TEST_HOME}/warn-lock.yaml"
  [ "$status" -eq 2 ]
  [[ "$output" == *"warning(s)"* ]]
}

@test "--check-age does not crash with 'command not found' (check_package_age regression)" {
  cat > "${TEST_HOME}/age-lock.yaml" <<'EOF'
packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-xxx}
EOF
  run bash "${REPO_ROOT}/bin/scan-lockfile" --check-age "${TEST_HOME}/age-lock.yaml"
  [[ "$output" != *"command not found"* ]]
  [[ "$output" == *"Phase 2: Publish-age check"* ]]
  [[ "$output" == *"Phase 3"* ]]
}

@test "a custom PNPM_SAFE_CACHE (documented override) does not crash the audit log write" {
  write_clean_lockfile
  export PNPM_SAFE_CACHE="${TEST_HOME}/somewhere/else"
  # Deliberately do NOT set PNPM_SAFE_AUDIT_LOG/PNPM_SAFE_LOG here — this
  # is exactly the scenario that used to crash: they default under
  # ~/.cache/pnpm-safe independently of PNPM_SAFE_CACHE, and that
  # directory was never created.
  unset PNPM_SAFE_AUDIT_LOG PNPM_SAFE_LOG
  run bash "${REPO_ROOT}/bin/scan-lockfile" "${TEST_HOME}/clean-lock.yaml"
  [ "$status" -eq 0 ]
  [[ "$output" != *"No such file or directory"* ]]
}

@test "--help exits 0 without requiring a lockfile to exist" {
  run bash "${REPO_ROOT}/bin/scan-lockfile" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"Usage:"* ]]
}

@test "missing lockfile is a clean, documented error (not a crash)" {
  run bash "${REPO_ROOT}/bin/scan-lockfile" "${TEST_HOME}/does-not-exist.yaml"
  [ "$status" -eq 1 ]
  [[ "$output" == *"Lockfile not found"* ]]
}
