#!/usr/bin/env bats
# tests/cache.bats — lib/cache.sh, and its new CLI wiring in bin/pnpm-safe.

load test_helper.bash

setup() { setup_isolated_env; }
teardown() { teardown_isolated_env; }

@test "--cache-stats reports entry count without crashing (regression: was unreachable dead code)" {
  echo '{}' > "${PNPM_SAFE_CACHE}/meta_lodash.json"
  run bash "${REPO_ROOT}/bin/pnpm-safe" --cache-stats
  [ "$status" -eq 0 ]
  [[ "$output" == *"Cache:"* ]]
  [[ "$output" == *"1 entries"* ]]
}

@test "--cache-clear removes cached metadata files" {
  echo '{}' > "${PNPM_SAFE_CACHE}/meta_lodash.json"
  run bash "${REPO_ROOT}/bin/pnpm-safe" --cache-clear
  [ "$status" -eq 0 ]
  [ ! -f "${PNPM_SAFE_CACHE}/meta_lodash.json" ]
}

@test "--cache-purge removes only entries older than the given age" {
  echo '{}' > "${PNPM_SAFE_CACHE}/meta_old.json"
  touch -d "48 hours ago" "${PNPM_SAFE_CACHE}/meta_old.json" 2>/dev/null \
    || touch -t "$(date -v-48H +%Y%m%d%H%M 2>/dev/null)" "${PNPM_SAFE_CACHE}/meta_old.json" 2>/dev/null \
    || true
  echo '{}' > "${PNPM_SAFE_CACHE}/meta_new.json"

  run bash "${REPO_ROOT}/bin/pnpm-safe" --cache-purge=24
  [ "$status" -eq 0 ]
  [ -f "${PNPM_SAFE_CACHE}/meta_new.json" ]
}
