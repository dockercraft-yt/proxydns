#!/usr/bin/env bash
# Regenerates the README screenshots in docs/screenshots/.
#
# Serves internal/web/static with a mock API (example data, no backend needed)
# and captures every page in German/English and light/dark with headless Chromium.
# Requirements: python3, chromium (or set CHROMIUM=/path/to/chrome).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/scripts/screenshots"
OUT="$ROOT/docs/screenshots"
CHROMIUM="${CHROMIUM:-chromium}"
PORT=8765

TMP="$(mktemp -d)"
python3 "$HERE/mock.py" "$ROOT/internal/web/static" "$PORT" &
MOCK=$!
trap 'kill $MOCK 2>/dev/null; rm -rf "$TMP"' EXIT

for _ in $(seq 50); do
  curl -sf "http://127.0.0.1:$PORT/api/info" >/dev/null && break
  sleep 0.2
done

mkdir -p "$OUT"
# page:width x height
PAGES="entries:1440x900 new:1440x1160 settings:1440x1500 audit:1440x820"

for lang in de en; do
  for theme in light dark; do
    if [ "$theme" = dark ]; then
      flags=(--force-dark-mode --blink-settings=preferredColorScheme=0)
    else
      flags=(--blink-settings=preferredColorScheme=1)
    fi
    for page in $PAGES; do
      name=${page%%:*}; size=${page##*:}
      # fresh profile per shot: the UI remembers the language in localStorage
      prof="$(mktemp -d -p "$TMP")"
      "$CHROMIUM" --headless=new --disable-gpu --hide-scrollbars --user-data-dir="$prof" \
        --lang="$lang" --accept-lang="$lang" "${flags[@]}" --window-size="${size/x/,}" \
        --virtual-time-budget=4000 --screenshot="$OUT/$name-$lang-$theme.png" \
        "http://127.0.0.1:$PORT/#/$name" >/dev/null 2>&1
      echo "  $name-$lang-$theme.png"
    done
  done
done
