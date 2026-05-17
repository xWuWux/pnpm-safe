# pnpm-safe

A supply-chain-aware wrapper around `pnpm` with a four-phase scan pipeline,
policy modes, behavioral risk scoring, and structured JSONL audit logging.

Informed by: Shai-Hulud 2.0 (Nov 2025), Mini Shai-Hulud TanStack wave
(CVE-2026-45321, May 2026), LiteLLM/TeamPCP PyPI wave (Mar 2026),
Stream.Security open-source analysis (May 2026).

---

## The fundamental insight

> IOC matching alone loses the arms race the moment the attack framework goes public.

The right architecture is:

```
Static IOC layer       (fast, offline — degrades as attackers rename files)
    +
Behavioral heuristics  (durable — fires on age, exotic sources, maintainer churn)
    +
Native pnpm hardening  (strongest — operates at resolver level, before execution)
    +
Install-time wrapper   (pre-execution gate — no race conditions)
```

This is what pnpm-safe implements.

---

## Scan pipeline

Every `pnpm-safe install/add/update` runs four phases:

```
Phase A — Offline IOC scan       no network, milliseconds
          ↓ known hashes, filenames, github: deps, campaign strings
Phase B — Registry metadata      networked, cached 6h
          ↓ behavioral scoring: age + maintainer churn + exotic sources + script patterns
Phase C — Dry-resolve gate       pnpm --lockfile-only (ci/paranoid modes)
          ↓ resolves graph without executing; re-scans resulting lockfile
Phase D — Post-install audit     persistence detection after pnpm completes
          ↓ .claude/, .vscode/, systemd, LaunchAgents, dead-man's switch
```

---

## Policy modes

```
--mode balanced   24h age gate, warn-only.       Low friction for active development.
--mode ci         72h age gate, hard fail,       Default for CI pipelines.
                  dry-resolve enabled.
--mode paranoid   7-day age gate, block all,     High-security environments.
                  dry-resolve enabled.
```

Select via flag or environment:
```bash
pnpm-safe --mode paranoid add lodash
PNPM_SAFE_MODE=ci pnpm-safe install
```

---

## Installation

```bash
git clone <this-repo>
cd pnpm-safe
bash install.sh
```

Alias in your shell:
```bash
alias pnpm='pnpm-safe'
```

---

## Usage

```bash
# Install with mode
pnpm-safe --mode ci install
pnpm-safe --mode paranoid add @tanstack/react-router

# Standalone lockfile scanner
scan-lockfile                           # Phase A only (fast, no network)
scan-lockfile --check-age               # + Phase B age checks
scan-lockfile --registry-full           # + full per-package registry checks
scan-lockfile --mode paranoid           # apply paranoid thresholds

# Nightly cron audit (persistence + hygiene)
nightly-audit                           # full home-dir + project scan
nightly-audit --project-only            # CI mode: CWD only

# Audit log
pnpm-safe --audit-tail 30              # last 30 JSONL events, formatted
```

---

## Native pnpm hardening (most important)

`pnpm-safe` is a complement to pnpm's built-in security settings, not a
replacement. Copy `hardening/pnpm-workspace.yaml` into your project root.

The three settings that would have blocked the TanStack attack outright:

| Setting | Why |
|---|---|
| `minimumReleaseAge: 10080` | Malicious packages were live for ~3h. A 7-day gate blocks the entire flash-publish attack class. |
| `blockExoticSubdeps: true` | Directly kills the `github:<orphan-commit>` optionalDependency propagation vector. |
| `allowBuilds: {}` (pnpm v11) | No `preinstall/postinstall/prepare` unless explicitly allowlisted — neutralizes lifecycle hook execution. |

```yaml
# pnpm-workspace.yaml — minimum viable hardening
minimumReleaseAge: 10080
blockExoticSubdeps: true
trustPolicy: no-downgrade
allowBuilds:
  esbuild: true
```

---

## Behavioral scoring (Phase B)

Rather than N independent binary checks, Phase B computes a composite risk
score per package. This is the durable layer — it fires on *behaviour*, not
on specific filenames or hashes that attackers mutate between variants.

| Signal | Points |
|---|---|
| Published < 1h ago | 50 |
| Published < 24h ago | 30 |
| Published < policy threshold | 15 |
| Maintainer removed since last version | +20 |
| Maintainer added since last version | +10 |
| Exotic source in optionalDependency | 40 |
| Known-malicious commit hash in optDep | 99 (always BLOCK) |
| Suspicious lifecycle script pattern | 40 |
| Long preinstall/postinstall/prepare | 10 |
| Rules-file BLOCK override | 99 |
| Rules-file WARN override | 15 |

Thresholds: `≥ 40` → BLOCK, `≥ 15` → WARN. Configurable.

---

## Audit log (JSONL)

Every decision is written to `~/.cache/pnpm-safe/audit.jsonl`:

```json
{"ts":"2026-05-11T14:23:01Z","session":"a3f9c1","mode":"ci","level":"BLOCK",
 "package":"@tanstack/react-router","version":"1.169.5",
 "reason":"Risk score 80 ≥ 40. Published 2h ago; exotic optionalDep github:tanstack/router#79ac49ee",
 "rules":["publish_age","exotic_optional_dep"],
 "cwd":"/home/user/project","git_ref":"abc1234","cmd":"pnpm add @tanstack/react-router"}
```

Feed to Splunk, Datadog, or any SIEM that ingests JSONL. Useful for:
- Incident response (what was installed when, by whom)
- CI auditing (did a blocked package get force-installed?)
- Trend analysis (which rule tags are firing most)

---

## Nightly audit cron

```bash
# Add to crontab
0 2 * * * /path/to/pnpm-safe/bin/nightly-audit >> ~/.cache/pnpm-safe/nightly.log 2>&1
```

Scans (6 checks):
1. Known persistence paths (`.claude/`, `.vscode/`, systemd units, LaunchAgents)
2. Campaign IOC strings in Claude Code session logs
3. Suspicious GitHub Actions workflow patterns (pull_request_target + actions/cache)
4. Lockfile IOC patterns
5. `node_modules` for known payload filenames
6. Git history for dead-drop commit author

Note: cron is a **hygiene** layer, not a primary prevention mechanism.
Primary prevention = `minimumReleaseAge` + `blockExoticSubdeps` + `allowBuilds`.

---

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `PNPM_SAFE_MODE` | `balanced` | Policy mode |
| `PNPM_SAFE_BLOCK` | `1` | `1` = block on BLOCK-level findings |
| `PNPM_SAFE_MIN_AGE` | *(from mode)* | Override age threshold in minutes |
| `PNPM_SAFE_CACHE_TTL` | `21600` | Registry cache TTL in seconds (6h) |
| `PNPM_SAFE_CACHE` | `~/.cache/pnpm-safe` | Cache directory |
| `PNPM_SAFE_AUDIT_LOG` | `~/.cache/pnpm-safe/audit.jsonl` | JSONL audit log |
| `PNPM_SAFE_AGE_EXCLUDE` | *(empty)* | Space-separated packages to skip age checks |

---

## Remediation (if compromised)

**Critical: disable the dead-man's switch BEFORE revoking any credentials.**
Token revocation triggers `rm -rf ~/` on infected machines.

```bash
# Linux
systemctl --user stop gh-token-monitor.service
systemctl --user disable gh-token-monitor.service
rm -f ~/.config/systemd/user/gh-token-monitor.service
rm -f ~/.local/bin/gh-token-monitor.sh

# macOS
launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
```

Then rotate credentials in order: npm publish tokens → GitHub PATs → AWS keys
→ Vault tokens → K8s service accounts → SSH keys → GCP credentials.

Audit `~/.claude/projects/*.jsonl` — Claude Code session logs are an explicit
harvest target in the TanStack wave payload.

---

## What this does NOT catch

- Old malicious packages that predate the attack (no age signal)
- Private registry packages without `time` metadata — set `minimumReleaseAgeIgnoreMissingTime: false` to fail-safe
- Post-install cloud control-plane abuse — use UEBA/CSPM (Stream.Security, Wiz) for that layer
- SLSA provenance bypass — the TanStack attack *produced* valid SLSA Build Level 3 provenance; provenance is necessary but not sufficient
