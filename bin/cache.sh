#!/usr/bin/env bash
# lib/cache.sh — cache management helpers

cache_purge() {
  local older_than_hours="${1:-24}"
  find "$CACHE_DIR" -name "meta_*.json" -mmin "+$(( older_than_hours * 60 ))" -delete
  info "Cache purged (entries older than ${older_than_hours}h removed)."
}

cache_stats() {
  local count size
  count=$(find "$CACHE_DIR" -name "meta_*.json" 2>/dev/null | wc -l)
  size=$(du -sh "$CACHE_DIR" 2>/dev/null | awk '{print $1}')
  info "Cache: ${count} entries, ${size} on disk (${CACHE_DIR})"
}

cache_clear() {
  rm -f "${CACHE_DIR}"/meta_*.json
  info "Cache cleared."
}
