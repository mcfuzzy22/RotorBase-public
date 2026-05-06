#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /var/backups/rotorbase/app-YYYYMMDDTHHMMSSZ.tar.gz" >&2
  exit 2
fi

BACKUP_FILE="$1"
APP_DIR="${APP_DIR:-/opt/rotorbase/app}"
SERVICE_NAME="${SERVICE_NAME:-rotorbase}"

if [[ ! -f "$BACKUP_FILE" ]]; then
  echo "Backup not found: $BACKUP_FILE" >&2
  exit 1
fi

restore_tmp="$(mktemp -d)"
trap 'rm -rf "$restore_tmp"' EXIT

tar -C "$restore_tmp" -xzf "$BACKUP_FILE"

if [[ ! -d "$restore_tmp/app" ]]; then
  echo "Backup does not contain an app directory" >&2
  exit 1
fi

systemctl stop "$SERVICE_NAME"
rsync -az --delete "$restore_tmp/app/" "$APP_DIR/"
systemctl start "$SERVICE_NAME"

echo "Rolled back using $BACKUP_FILE"
