#!/usr/bin/env bash
# lib/registry.sh — npm registry metadata fetcher
# Uses local disk cache to avoid hammering the registry on every install.
# Cache TTL is controlled by PNPM_SAFE_CACHE_TTL (default 6h = 21600s).

# Resolve package name and optional version from a spec like:
#   lodash, lodash@4.17.21, @tanstack/react-router@1.169.5
parse_package_spec() {
  local spec="$1"
  local name version
  if [[ "$spec" == @* ]]; then
    # scoped: @scope/name@version
    local scope_name="${spec%%@*[^@]}"  # everything before the last @
    # Simpler approach: split on @ carefully
    if [[ "$spec" =~ ^(@[^@]+)@(.+)$ ]]; then
      name="${BASH_REMATCH[1]}"
      version="${BASH_REMATCH[2]}"
    else
      name="$spec"
      version=""
    fi
  else
    name="${spec%%@*}"
    version="${spec#*@}"
    [[ "$name" == "$version" ]] && version=""  # no @ found
  fi
  echo "$name" "$version"
}

# Fetch full registry metadata for a package, with disk cache.
# Prints the JSON to stdout; returns 1 on failure.
fetch_registry_meta() {
  local pkg_name="$1"
  local cache_key
  cache_key="$(echo "$pkg_name" | tr '/' '_')"
  local cache_file="${CACHE_DIR}/meta_${cache_key}.json"

  # Cache hit check
  if [[ -f "$cache_file" ]]; then
    local age=$(( $(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0) ))
    if [[ "$age" -lt "$CACHE_TTL" ]]; then
      cat "$cache_file"
      return 0
    fi
  fi

  # Fetch from registry
  local encoded="${pkg_name//@/%40}"
  encoded="${encoded//\//%2F}"
  local url="https://registry.npmjs.org/${pkg_name}"

  local result
  result=$(curl -sf --max-time 10 \
    -H "Accept: application/vnd.npm.install-v1+json" \
    "$url" 2>/dev/null) || {
    warn "  registry fetch failed for ${pkg_name} (offline?)"
    return 1
  }

  echo "$result" | tee "$cache_file"
}

# Get the publish timestamp (epoch seconds) for a specific version.
# Returns empty string if not found.
get_version_publish_time() {
  local pkg_name="$1"
  local version="$2"
  local meta
  meta=$(fetch_registry_meta "$pkg_name") || return 1

  # Extract time from .time["<version>"]  — ISO8601 → epoch
  local iso
  iso=$(echo "$meta" | python3 -c "
import sys, json
data = json.load(sys.stdin)
times = data.get('time', {})
v = sys.argv[1]
if v in times:
    print(times[v])
" "$version" 2>/dev/null)

  [[ -z "$iso" ]] && return 1

  # Convert ISO8601 to epoch
  date -d "$iso" +%s 2>/dev/null || \
    python3 -c "
from datetime import datetime, timezone
s = '${iso}'
# Strip trailing Z, parse
s = s.rstrip('Z').split('+')[0]
dt = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
print(int(dt.timestamp()))
" 2>/dev/null
}

# Get the latest dist-tag version
get_latest_version() {
  local pkg_name="$1"
  local meta
  meta=$(fetch_registry_meta "$pkg_name") || return 1
  echo "$meta" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('dist-tags', {}).get('latest', ''))
" 2>/dev/null
}

# Get maintainer list for a specific version (returns newline-separated names)
get_version_maintainers() {
  local pkg_name="$1"
  local version="$2"
  local meta
  meta=$(fetch_registry_meta "$pkg_name") || return 1
  echo "$meta" | python3 -c "
import sys, json
data = json.load(sys.stdin)
versions = data.get('versions', {})
vdata = versions.get(sys.argv[1], {})
for m in vdata.get('maintainers', []):
    print(m.get('name',''))
" "$version" 2>/dev/null
}

# Get the optionalDependencies of a specific version (key=value pairs)
get_version_optional_deps() {
  local pkg_name="$1"
  local version="$2"
  local meta
  meta=$(fetch_registry_meta "$pkg_name") || return 1
  echo "$meta" | python3 -c "
import sys, json
data = json.load(sys.stdin)
vdata = data.get('versions', {}).get(sys.argv[1], {})
for k, v in vdata.get('optionalDependencies', {}).items():
    print(f'{k}={v}')
" "$version" 2>/dev/null
}

# Get the lifecycle scripts of a specific version
get_version_scripts() {
  local pkg_name="$1"
  local version="$2"
  local meta
  meta=$(fetch_registry_meta "$pkg_name") || return 1
  echo "$meta" | python3 -c "
import sys, json
data = json.load(sys.stdin)
vdata = data.get('versions', {}).get(sys.argv[1], {})
for k, v in vdata.get('scripts', {}).items():
    print(f'{k}={v}')
" "$version" 2>/dev/null
}

# Extract direct dependency names from package.json
extract_deps_from_package_json() {
  local pkg_json="$1"
  python3 -c "
import sys, json
with open(sys.argv[1]) as f:
    data = json.load(f)
deps = {}
deps.update(data.get('dependencies', {}))
deps.update(data.get('devDependencies', {}))
for name in deps:
    print(name)
" "$pkg_json" 2>/dev/null
}
