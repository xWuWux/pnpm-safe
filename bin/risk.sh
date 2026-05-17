#!/usr/bin/env bash
# lib/risk.sh — per-package behavioral risk analysis
#
# Scoring model (per recommendation: durable heuristics over IOC signatures):
#
#   Signal                              Points  Level threshold
#   ─────────────────────────────────── ──────  ────────────────
#   Published < 1h ago                    50    BLOCK  (≥ 40)
#   Published < 24h ago                   30    BLOCK
#   Published < threshold ago             15    WARN   (≥ 15)
#   Maintainer removed since last ver     20    WARN
#   Maintainer added since last ver       10    WARN
#   Exotic source in optionalDep          40    BLOCK
#   Known-malicious commit in optDep      99    BLOCK (always)
#   Suspicious lifecycle script pattern   40    BLOCK
#   Long preinstall/postinstall/prepare   10    WARN
#   Rules-file BLOCK override             99    BLOCK (always)
#   Rules-file WARN override              15    WARN
#
# A composite score per package replaces N independent warn/block calls.
# The score is emitted to the JSONL audit log for trend analysis.
#
# Durable insight from PyPI worm analysis: attackers mutate filenames and
# infrastructure faster than defenders can update signatures. These heuristics
# fire on BEHAVIOUR (age, maintainer churn, exotic sources, script obfuscation)
# — invariant across campaign variants.

MIN_RELEASE_AGE_MINUTES="${PNPM_SAFE_MIN_AGE:-1440}"
AGE_EXCLUDE_PACKAGES="${PNPM_SAFE_AGE_EXCLUDE:-}"
RULES_FILE="${RULES_DIR}/suspicious.conf"

SCORE_BLOCK_THRESHOLD=40
SCORE_WARN_THRESHOLD=15

is_age_excluded() {
  local pkg="$1"
  for ex in $AGE_EXCLUDE_PACKAGES; do [[ "$pkg" == "$ex" ]] && return 0; done
  return 1
}

# ── Main entry point ─────────────────────────────────────────────────────────

check_package() {
  local spec="$1"
  local pkg_name pkg_version
  read -r pkg_name pkg_version <<< "$(parse_package_spec "$spec")"

  if [[ -z "$pkg_version" ]]; then
    pkg_version=$(get_latest_version "$pkg_name") || {
      warn "    Could not resolve version for ${pkg_name} (offline?)"
      return 0
    }
  fi
  [[ -z "$pkg_version" ]] && return 0

  info "    Scoring: ${pkg_name}@${pkg_version}"

  # Accumulate score signals for this package
  local score=0
  declare -a matched_rules=()
  declare -a findings=()

  # ── 1. Publish age ────────────────────────────────────────────────────────
  if ! is_age_excluded "$pkg_name"; then
    local age_result
    age_result=$(score_publish_age "$pkg_name" "$pkg_version")
    local age_score="${age_result%%:*}"
    local age_msg="${age_result#*:}"
    if [[ "$age_score" -gt 0 ]]; then
      score=$(( score + age_score ))
      matched_rules+=("publish_age")
      findings+=("${age_msg}")
    fi
  fi

  # ── 2. Maintainer change ──────────────────────────────────────────────────
  local maint_result
  maint_result=$(score_maintainer_change "$pkg_name" "$pkg_version")
  local maint_score="${maint_result%%:*}"
  local maint_msg="${maint_result#*:}"
  if [[ "$maint_score" -gt 0 ]]; then
    score=$(( score + maint_score ))
    matched_rules+=("maintainer_churn")
    findings+=("${maint_msg}")
  fi

  # ── 3. Exotic optionalDependency sources ──────────────────────────────────
  local opt_result
  opt_result=$(score_optional_deps "$pkg_name" "$pkg_version")
  local opt_score="${opt_result%%:*}"
  local opt_msg="${opt_result#*:}"
  if [[ "$opt_score" -gt 0 ]]; then
    score=$(( score + opt_score ))
    matched_rules+=("exotic_optional_dep")
    findings+=("${opt_msg}")
  fi

  # ── 4. Lifecycle script anomalies ─────────────────────────────────────────
  local script_result
  script_result=$(score_lifecycle_scripts "$pkg_name" "$pkg_version")
  local script_score="${script_result%%:*}"
  local script_msg="${script_result#*:}"
  if [[ "$script_score" -gt 0 ]]; then
    score=$(( score + script_score ))
    matched_rules+=("lifecycle_script")
    findings+=("${script_msg}")
  fi

  # ── 5. Rules file overrides ───────────────────────────────────────────────
  if [[ -f "$RULES_FILE" ]]; then
    local rules_result
    rules_result=$(score_rules_file "$pkg_name" "$pkg_version")
    local rules_score="${rules_result%%:*}"
    local rules_msg="${rules_result#*:}"
    if [[ "$rules_score" -gt 0 ]]; then
      score=$(( score + rules_score ))
      matched_rules+=("rules_file")
      findings+=("${rules_msg}")
    fi
  fi

  # ── Decision: emit one structured event per package ───────────────────────
  if [[ "$score" -ge "$SCORE_BLOCK_THRESHOLD" ]]; then
    local summary
    summary=$(IFS='; '; echo "${findings[*]}")
    flag_risk_v "BLOCK" "$pkg_name" "$pkg_version" \
      "Risk score ${score} ≥ ${SCORE_BLOCK_THRESHOLD} (block threshold). ${summary}" \
      "${matched_rules[@]+"${matched_rules[@]}"}"
  elif [[ "$score" -ge "$SCORE_WARN_THRESHOLD" ]]; then
    local summary
    summary=$(IFS='; '; echo "${findings[*]}")
    flag_risk_v "WARN" "$pkg_name" "$pkg_version" \
      "Risk score ${score} ≥ ${SCORE_WARN_THRESHOLD} (warn threshold). ${summary}" \
      "${matched_rules[@]+"${matched_rules[@]}"}"
  else
    log_allow "$pkg_name" "$pkg_version"
  fi
}

# ── Scoring functions — each returns "SCORE:message" ─────────────────────────

score_publish_age() {
  local pkg_name="$1" version="$2"

  local publish_epoch
  publish_epoch=$(get_version_publish_time "$pkg_name" "$version") || { echo "0:"; return; }
  [[ -z "$publish_epoch" ]] && { echo "0:"; return; }

  local now_epoch; now_epoch=$(date +%s)
  local age_min=$(( (now_epoch - publish_epoch) / 60 ))
  local age_h=$(( age_min / 60 ))
  local req_h=$(( MIN_RELEASE_AGE_MINUTES / 60 ))

  if [[ "$age_min" -lt 60 ]]; then
    echo "50:Published only ${age_min}m ago — extreme freshness (TanStack attack window was ~3h)"
  elif [[ "$age_min" -lt 1440 ]]; then
    echo "30:Published ${age_h}h ago — below ${req_h}h threshold"
  elif [[ "$age_min" -lt "$MIN_RELEASE_AGE_MINUTES" ]]; then
    echo "15:Published ${age_h}h ago — fresher than ${req_h}h policy"
  else
    echo "0:"
  fi
}

score_maintainer_change() {
  local pkg_name="$1" version="$2"

  # Only check packages < 7 days old (older changes are likely legitimate)
  local publish_epoch
  publish_epoch=$(get_version_publish_time "$pkg_name" "$version") || { echo "0:"; return; }
  local age_h=$(( ($(date +%s) - publish_epoch) / 3600 ))
  [[ "$age_h" -gt 168 ]] && { echo "0:"; return; }

  local meta
  meta=$(fetch_registry_meta "$pkg_name") || { echo "0:"; return; }

  local prev_version
  prev_version=$(echo "$meta" | python3 -c "
import sys,json
data=json.load(sys.stdin)
vs=sorted(data.get('versions',{}).keys())
t=sys.argv[1]; idx=vs.index(t) if t in vs else -1
if idx>0: print(vs[idx-1])
" "$version" 2>/dev/null)
  [[ -z "$prev_version" ]] && { echo "0:"; return; }

  local cur prev
  cur=$(get_version_maintainers "$pkg_name" "$version" | sort)
  prev=$(get_version_maintainers "$pkg_name" "$prev_version" | sort)
  [[ -z "$cur" || -z "$prev" ]] && { echo "0:"; return; }

  local removed added
  removed=$(comm -23 <(echo "$prev") <(echo "$cur") | tr '\n' ',')
  added=$(comm -13 <(echo "$prev") <(echo "$cur") | tr '\n' ',')

  local score=0 msg=""
  [[ -n "$removed" ]] && { score=$(( score + 20 )); msg+="Maintainer(s) removed: ${removed%; }. "; }
  [[ -n "$added"   ]] && { score=$(( score + 10 )); msg+="Maintainer(s) added: ${added%; } (vs ${prev_version})."; }

  echo "${score}:${msg}"
}

score_optional_deps() {
  local pkg_name="$1" version="$2"

  local opt_deps
  opt_deps=$(get_version_optional_deps "$pkg_name" "$version") || { echo "0:"; return; }
  [[ -z "$opt_deps" ]] && { echo "0:"; return; }

  local score=0 msg=""
  while IFS='=' read -r dep_name dep_spec; do
    [[ -z "$dep_name" ]] && continue
    # Known-malicious commit → immediate block score
    for bad in "${MALICIOUS_COMMIT_HASHES[@]}"; do
      if [[ "$dep_spec" == *"$bad"* ]]; then
        echo "99:KNOWN MALICIOUS commit in optionalDep ${dep_name}=${dep_spec}"
        return
      fi
    done
    # Exotic source patterns
    for pattern in "${SUSPICIOUS_OPT_DEP_PATTERNS[@]}"; do
      if [[ "$dep_spec" == *"$pattern"* ]]; then
        score=$(( score + 40 ))
        msg+="Exotic optionalDep ${dep_name}=${dep_spec} (pattern: ${pattern}). "
        break
      fi
    done
  done <<< "$opt_deps"

  echo "${score}:${msg}"
}

score_lifecycle_scripts() {
  local pkg_name="$1" version="$2"

  local scripts
  scripts=$(get_version_scripts "$pkg_name" "$version") || { echo "0:"; return; }
  [[ -z "$scripts" ]] && { echo "0:"; return; }

  local score=0 msg=""
  while IFS='=' read -r script_name script_cmd; do
    [[ -z "$script_name" ]] && continue
    for pattern in "${SUSPICIOUS_SCRIPT_PATTERNS[@]}"; do
      if [[ "$script_cmd" == *"$pattern"* ]]; then
        score=$(( score + 40 ))
        msg+="Script '${script_name}' matches IOC pattern '${pattern}'. "
        break
      fi
    done
    # Long hooks in install-time scripts are elevated risk
    if [[ "$script_name" =~ ^(preinstall|postinstall|prepare)$ && ${#script_cmd} -gt 200 ]]; then
      score=$(( score + 10 ))
      msg+="Long ${script_name} script (${#script_cmd} chars). "
    fi
  done <<< "$scripts"

  echo "${score}:${msg}"
}

score_rules_file() {
  local pkg_name="$1" version="$2"

  local score=0 msg=""
  while IFS= read -r line; do
    [[ "$line" =~ ^# || -z "$line" ]] && continue
    local level pattern reason
    read -r level pattern reason <<< "$line"
    if [[ "$pkg_name" == $pattern ]]; then
      case "$level" in
        BLOCK) score=$(( score + 99 )); msg+="Rules file BLOCK: ${reason}. " ;;
        WARN)  score=$(( score + 15 )); msg+="Rules file WARN: ${reason}. " ;;
      esac
    fi
  done < "$RULES_FILE"

  echo "${score}:${msg}"
}
