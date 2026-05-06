#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-rotorbase}"
LOCAL_URL="${LOCAL_URL:-http://127.0.0.1:5048/}"
PUBLIC_URL="${PUBLIC_URL:-https://boostedrotary.com/}"

systemctl is-active --quiet "$SERVICE_NAME"

local_status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$LOCAL_URL")"
public_status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$PUBLIC_URL")"

if [[ "$local_status" != "200" ]]; then
  echo "Local health check failed: $LOCAL_URL returned $local_status" >&2
  exit 1
fi

if [[ "$public_status" != "200" ]]; then
  echo "Public health check failed: $PUBLIC_URL returned $public_status" >&2
  exit 1
fi

echo "$SERVICE_NAME is active; local=$local_status public=$public_status"
