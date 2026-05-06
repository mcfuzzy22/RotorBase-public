#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-rotorbase}"
LOCAL_URL="${LOCAL_URL:-http://127.0.0.1:5048/}"
PUBLIC_URL="${PUBLIC_URL:-https://boostedrotary.com/}"

systemctl is-active --quiet "$SERVICE_NAME"

check_url() {
  local url="$1"
  local timeout="$2"
  local status

  for _ in {1..15}; do
    status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time "$timeout" "$url" 2>/dev/null || true)"
    if [[ "$status" == "200" ]]; then
      echo "$status"
      return 0
    fi
    sleep 1
  done

  echo "${status:-000}"
  return 1
}

local_status="$(check_url "$LOCAL_URL" 15 || true)"
public_status="$(check_url "$PUBLIC_URL" 20 || true)"

if [[ "$local_status" != "200" ]]; then
  echo "Local health check failed: $LOCAL_URL returned $local_status" >&2
  exit 1
fi

if [[ "$public_status" != "200" ]]; then
  echo "Public health check failed: $PUBLIC_URL returned $public_status" >&2
  exit 1
fi

echo "$SERVICE_NAME is active; local=$local_status public=$public_status"
