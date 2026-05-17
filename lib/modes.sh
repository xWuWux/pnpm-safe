#!/usr/bin/env bash
# lib/modes.sh — policy mode definitions
#
# Modes control the balance between security and developer friction.
# The goal: make the "safe" mode easy enough that teams don't disable the tool.
#
# Select mode via:
#   pnpm-safe --mode paranoid add lodash
#   PNPM_SAFE_MODE=ci pnpm-safe install
#
# Mode     | minimumReleaseAge | allowBuilds check | on finding  | dry-resolve
# ---------|-------------------|-------------------|-------------|------------
# balanced | 24h  (1440m)      | warn unknown      | warn        | no
# ci       | 72h  (4320m)      | block unknown     | fail hard   | yes
# paranoid | 7d   (10080m)     | block unknown     | block       | yes

declare -A MODE_MIN_AGE=(
  [balanced]=1440
  [ci]=4320
  [paranoid]=10080
)

declare -A MODE_BLOCK_ON_RISK=(
  [balanced]=0       # warn only
  [ci]=1             # block
  [paranoid]=1       # block
)

declare -A MODE_DRY_RESOLVE=(
  [balanced]=0
  [ci]=1
  [paranoid]=1
)

declare -A MODE_BUILD_POLICY=(
  [balanced]="warn"  # warn about unknown build scripts
  [ci]="block"       # block unknown build scripts
  [paranoid]="block" # block unknown build scripts
)

declare -A MODE_DESCRIPTIONS=(
  [balanced]="24h age gate, warn-only. Low friction for active development."
  [ci]="72h age gate, hard fail, dry-resolve. Good default for CI pipelines."
  [paranoid]="7-day age gate, block all, dry-resolve. High-security environments."
)

apply_mode() {
  local mode="${PNPM_SAFE_MODE:-balanced}"

  # Override from CLI arg if given
  if [[ -n "${CLI_MODE:-}" ]]; then
    mode="$CLI_MODE"
  fi

  case "$mode" in
    balanced|ci|paranoid) ;;
    *)
      warn "Unknown mode '${mode}'. Valid modes: balanced, ci, paranoid. Defaulting to balanced."
      mode="balanced"
      ;;
  esac

  # Apply mode settings (only if not already overridden by explicit env vars)
  export ACTIVE_MODE="$mode"

  if [[ -z "${PNPM_SAFE_MIN_AGE_EXPLICIT:-}" ]]; then
    MIN_RELEASE_AGE_MINUTES="${MODE_MIN_AGE[$mode]}"
  fi

  if [[ -z "${PNPM_SAFE_BLOCK_EXPLICIT:-}" ]]; then
    BLOCK_ON_RISK="${MODE_BLOCK_ON_RISK[$mode]}"
  fi

  if [[ -z "${PNPM_SAFE_DRY_RESOLVE_EXPLICIT:-}" ]]; then
    DRY_RESOLVE="${MODE_DRY_RESOLVE[$mode]}"
  fi

  BUILD_POLICY="${MODE_BUILD_POLICY[$mode]}"

  info "  Mode: ${mode} — ${MODE_DESCRIPTIONS[$mode]}"
}

# Print mode summary for --help / --list-modes
list_modes() {
  echo ""
  echo "Available modes (--mode <name> or PNPM_SAFE_MODE=<name>):"
  echo ""
  printf "  %-12s %s\n" "balanced" "${MODE_DESCRIPTIONS[balanced]}"
  printf "  %-12s %s\n" "ci"       "${MODE_DESCRIPTIONS[ci]}"
  printf "  %-12s %s\n" "paranoid" "${MODE_DESCRIPTIONS[paranoid]}"
  echo ""
  echo "Environment overrides (take precedence over mode):"
  echo "  PNPM_SAFE_MIN_AGE=<minutes>   Override minimum release age"
  echo "  PNPM_SAFE_BLOCK=0|1           Override block-on-risk setting"
  echo ""
}
