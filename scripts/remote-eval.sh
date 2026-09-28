#!/usr/bin/env bash
# Run a snippet inside the paired VRCNext page through the bridge's `remote` service.
#
# Usage:
#   remote-eval.sh 'return document.title'
#   remote-eval.sh - < snippet.js
#   remote-eval.sh --timeout 20000 'await sleep(1000); return text("#tab9 h2")'
#
# The snippet is the body of an async function. `host` (the plugin host handle), `manager` and the helpers
# `text(sel)`, `click(sel)`, `visible(sel)`, `rects(sel)` and `sleep(ms)` are in scope.
# Requires the bridge to run with `--dev`; the token comes from the data directory.
set -euo pipefail

endpoint="${VRCNEXT_BRIDGE_ENDPOINT:-http://127.0.0.1:42081}"
data_dir="${VRCNEXT_BRIDGE_DATA_DIR:-$HOME/.vrcnext-plugins}"
timeout_ms=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) timeout_ms="$2"; shift 2 ;;
    --endpoint) endpoint="$2"; shift 2 ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) break ;;
  esac
done

if [[ $# -lt 1 ]]; then
  echo "usage: $(basename "$0") [--timeout ms] [--endpoint url] <code|->" >&2
  exit 2
fi

if [[ "$1" == "-" ]]; then
  code="$(cat)"
else
  code="$1"
fi

token="$(<"$data_dir/token")"

body="$(jq -cn --arg code "$code" --arg t "$timeout_ms" \
  '{code: $code} + (if $t == "" then {} else {timeoutMs: ($t | tonumber)} end)')"

response="$(curl -sS -X POST "$endpoint/v1/remote/eval" \
  -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' \
  --data "$body")"

# The transport wraps failures as {ok:false,error:{code,message}}; the page's own outcome is
# {ok,value,error}. Print the value on success, the message on either kind of failure.
if [[ "$(jq -r '.ok' <<<"$response")" == "true" ]]; then
  jq '.value' <<<"$response"
else
  jq -r '.error | if type == "object" then "\(.code): \(.message)" else . end' <<<"$response" >&2
  exit 1
fi
