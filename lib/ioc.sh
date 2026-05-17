#!/usr/bin/env bash
# lib/ioc.sh — Known Indicators of Compromise
#
# Patterns derived from:
#   - Shai-Hulud 2.0 (Nov 2025): setup_bun.js / bun_environment.js / preinstall
#   - Mini Shai-Hulud (Apr 2026): SAP/Intercom ecosystems, .claude/settings.json persistence
#   - Mini Shai-Hulud "TanStack wave" (May 11, 2026): CVE-2026-45321 / GHSA-g7cv-rxg3-hmpx
#   - LiteLLM/TeamPCP PyPI wave (Mar 2026): .pth startup hooks
#   - Stream.Security open-source analysis (May 2026)
#
# When the worm goes open source, IOC lists expire fast.
# These patterns are most useful as a belt-and-suspenders layer alongside
# pnpm's native minimumReleaseAge + blockExoticSubdeps.

# ── Known malicious file names (payload carriers) ───────────────────────────
# Sources: deobfuscation analysis, Snyk Security Database, Upwind Security

MALICIOUS_FILENAMES=(
  "router_init.js"          # TanStack wave (May 2026) — SHA256 ab4fcadaec49c03...
  "tanstack_runner.js"      # TanStack wave secondary payload
  "setup_bun.js"            # Shai-Hulud 1.0 / 2.0
  "bun_environment.js"      # Shai-Hulud 1.0 / 2.0
  "vite_setup.mjs"          # TanStack wave cache-poisoning artifact
  "router_runtime.js"       # Persistence copy in .claude/
)

# ── Known malicious SHA256 hashes ───────────────────────────────────────────
declare -A MALICIOUS_HASHES
MALICIOUS_HASHES["ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"]="router_init.js (TanStack wave, CVE-2026-45321)"
MALICIOUS_HASHES["2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"]="tanstack_runner.js (TanStack wave)"

# ── Suspicious optionalDependency URL patterns ───────────────────────────────
# The TanStack attack used: "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
# blockExoticSubdeps in pnpm catches this natively, but we flag it explicitly.

SUSPICIOUS_OPT_DEP_PATTERNS=(
  "github:"            # git URL dep in optionalDependencies — primary TanStack vector
  "git+"               # git protocol dep
  "git://"             # git protocol dep
  "bitbucket:"         # uncommon in prod optionalDeps
  "gitlab:"            # uncommon in prod optionalDeps
)

# Specific orphan commit that was the TanStack attack's payload anchor
MALICIOUS_COMMIT_HASHES=(
  "79ac49eedf774dd4b0cfa308722bc463cfe5885c"
)

# ── Malicious lifecycle script patterns ──────────────────────────────────────
# The "&&exit 1" pattern in prepare scripts: runs payload, appears to fail gracefully
SUSPICIOUS_SCRIPT_PATTERNS=(
  "&&exit 1"           # evasion: run and silently fail
  "&& exit 1"          # same with space
  "tanstack_runner"    # explicit payload reference
  "router_runtime"     # explicit payload reference
  "setup_bun"          # Shai-Hulud 1.0/2.0 payload
  "__DAEMONIZED"        # daemonization env var check (from deobfuscation)
  "EveryBoiWeBuildIsAWormyBoi"  # campaign string from PBKDF2 deobfuscation
  "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"  # dead-man's switch string
)

# ── C2 / exfil infrastructure domains ───────────────────────────────────────
# Block at DNS level; listed here for log correlation
MALICIOUS_DOMAINS=(
  "filev2.getsession.org"
  "seed1.getsession.org"
  "seed2.getsession.org"
  "seed3.getsession.org"
  "api.masscan.cloud"
  "git-tanstack.com"
  "litter.catbox.moe"
  "models.litellm.cloud"
  "sfrclak.com"
)

# ── Dead-drop author pattern ─────────────────────────────────────────────────
# Attacker impersonated the Anthropic Claude GitHub App
MALICIOUS_COMMIT_AUTHOR="claude@users.noreply.github.com"
MALICIOUS_BRANCH_PATTERN="dependabout/"   # note: typo is intentional

# ── PBKDF2 campaign salt (useful for YARA rules on binaries) ─────────────────
CAMPAIGN_PBKDF2_SALT="svksjrhjkcejg"

# ── Persistence paths to check after install ─────────────────────────────────
PERSISTENCE_PATHS=(
  ".claude/router_runtime.js"
  ".claude/setup.mjs"
  ".vscode/setup.mjs"
  ".github/workflows/codeql_analysis.yml"
)

# ── Lockfile scanner ─────────────────────────────────────────────────────────
scan_lockfile_iocs() {
  local lockfile="$1"
  local found=0

  # 1. github: optionalDependencies (primary TanStack attack vector)
  if grep -qP 'github:[^"]+#[0-9a-f]{40}' "$lockfile" 2>/dev/null; then
    local matches
    matches=$(grep -oP 'github:[^"]+#[0-9a-f]{40}' "$lockfile")
    while IFS= read -r match; do
      # Check against known malicious commit hashes
      local commit
      commit="${match##*#}"
      for bad_commit in "${MALICIOUS_COMMIT_HASHES[@]}"; do
        if [[ "$commit" == "$bad_commit" ]]; then
          flag_risk "BLOCK" "lockfile" "KNOWN MALICIOUS commit hash in dep: ${match}" "known_ioc_hash"
          found=1
        fi
      done
      # Flag all github: optionalDep patterns regardless
      flag_risk "WARN" "lockfile" "github: URL dependency detected (exotic source): ${match}" "exotic_source"
      found=1
    done <<< "$matches"
  fi

  # 2. Known malicious payload filenames referenced in lockfile
  for fname in "${MALICIOUS_FILENAMES[@]}"; do
    if grep -q "$fname" "$lockfile" 2>/dev/null; then
      flag_risk "BLOCK" "lockfile" "Known malicious payload filename in lockfile: ${fname}" "payload_filename"
      found=1
    fi
  done

  # 3. Campaign-specific strings
  for pattern in "EveryBoiWeBuildIsAWormyBoi" "svksjrhjkcejg" "__DAEMONIZED" "OhNoWhatsGoingOnWithGitHub"; do
    if grep -q "$pattern" "$lockfile" 2>/dev/null; then
      flag_risk "BLOCK" "lockfile" "Campaign IOC string found in lockfile: ${pattern}" "campaign_string"
      found=1
    fi
  done

  # 4. Dead-drop author in git history (if in a git repo)
  if git rev-parse --git-dir &>/dev/null; then
    local bad_commits
    bad_commits=$(git log --all --author="$MALICIOUS_COMMIT_AUTHOR" --format="%H %s" 2>/dev/null || true)
    if [[ -n "$bad_commits" ]]; then
      flag_risk "BLOCK" "git-history" "Dead-drop commits from ${MALICIOUS_COMMIT_AUTHOR}: ${bad_commits}" "deadrop_commit"
      found=1
    fi
  fi

  # 5. Persistence file check
  for path in "${PERSISTENCE_PATHS[@]}"; do
    if [[ -f "$path" ]]; then
      # Check content for campaign strings
      for pattern in "router_runtime" "setup.mjs" "tanstack_runner" "__DAEMONIZED"; do
        if grep -q "$pattern" "$path" 2>/dev/null; then
          flag_risk "BLOCK" "$path" "Persistence file with IOC string '${pattern}' present on disk" "campaign_string"
          found=1
          break
        fi
      done
    fi
  done

  [[ "$found" -eq 0 ]] && return 0 || return 1
}

# ── Tarball IOC scanner (for already-downloaded tarballs) ──────────────────
scan_tarball_iocs() {
  local tarball="$1"
  local pkg_name="$2"

  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf $tmpdir" RETURN

  tar -xzf "$tarball" -C "$tmpdir" 2>/dev/null || return 0

  # Check for malicious payload files
  for fname in "${MALICIOUS_FILENAMES[@]}"; do
    if find "$tmpdir" -name "$fname" -type f | grep -q .; then
      flag_risk "BLOCK" "$pkg_name" "Known malicious payload file '${fname}' found inside tarball" "payload_filename"
    fi
  done

  # Check SHA256 of all .js files against known-bad hashes
  while IFS= read -r jsfile; do
    local hash
    hash=$(sha256sum "$jsfile" | awk '{print $1}')
    if [[ -n "${MALICIOUS_HASHES[$hash]:-}" ]]; then
      flag_risk "BLOCK" "$pkg_name" "Known malicious file hash: ${MALICIOUS_HASHES[$hash]} (${hash})" "payload_filename"
    fi
  done < <(find "$tmpdir" -name "*.js" -o -name "*.mjs" | head -50)

  # Check package.json for suspicious optionalDeps and scripts
  if [[ -f "$tmpdir/package/package.json" ]]; then
    # optionalDependencies with github: URLs
    for pattern in "${SUSPICIOUS_OPT_DEP_PATTERNS[@]}"; do
      if python3 -c "
import json, sys
with open('$tmpdir/package/package.json') as f:
    data = json.load(f)
opt = data.get('optionalDependencies', {})
for k, v in opt.items():
    if '$pattern' in v:
        print(f'{k}={v}')
        sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        flag_risk "BLOCK" "$pkg_name" "Exotic source in optionalDependencies: ${pattern} pattern" "exotic_source"
      fi
    done

    # prepare script with &&exit 1 evasion
    for pattern in "${SUSPICIOUS_SCRIPT_PATTERNS[@]}"; do
      if python3 -c "
import json, sys
with open('$tmpdir/package/package.json') as f:
    data = json.load(f)
scripts = data.get('scripts', {})
for k, v in scripts.items():
    if '$pattern' in v:
        print(f'{k}: {v}')
        sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        flag_risk "BLOCK" "$pkg_name" "Suspicious lifecycle script pattern '${pattern}'" "lifecycle_script"
      fi
    done
  fi
}

# ── Post-install persistence check ──────────────────────────────────────────
# Call after pnpm completes to detect if the install injected persistence
check_persistence_after_install() {
  local found=0
  for path in "${PERSISTENCE_PATHS[@]}"; do
    if [[ -f "$path" ]]; then
      warn "  ⚠️  Persistence file appeared after install: ${path}"
      warn "     This may indicate a compromised package executed lifecycle hooks."
      warn "     Check: cat ${path}"
      found=1
    fi
  done
  # Also check for the dead-man's switch systemd/launchd unit
  local dm_linux="${HOME}/.config/systemd/user/gh-token-monitor.service"
  local dm_mac="${HOME}/Library/LaunchAgents/com.user.gh-token-monitor.plist"
  for dm in "$dm_linux" "$dm_mac"; do
    if [[ -f "$dm" ]]; then
      flag_risk "BLOCK" "system" "Dead-man's switch persistence found: ${dm}" "persistence"
      error ""
      error "  ⚠️  CRITICAL: Do NOT revoke GitHub tokens before disabling this service."
      error "  Token revocation triggers home directory destruction (rm -rf ~/)."
      error ""
      error "  Linux remediation:"
      error "    systemctl --user stop gh-token-monitor.service"
      error "    systemctl --user disable gh-token-monitor.service"
      error "    rm -f ${dm_linux}"
      error "    rm -f ${HOME}/.local/bin/gh-token-monitor.sh"
      error ""
      error "  macOS remediation:"
      error "    launchctl unload ${dm_mac}"
      error "    rm -f ${dm_mac}"
      found=1
    fi
  done
  return $found
}
