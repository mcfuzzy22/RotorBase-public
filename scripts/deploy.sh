#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLISH_DIR="${PUBLISH_DIR:-/tmp/rotorbase-publish}"
APP_DIR="${APP_DIR:-/opt/rotorbase/app}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/rotorbase}"
SERVICE_NAME="${SERVICE_NAME:-rotorbase}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_file="${BACKUP_ROOT}/app-${timestamp}.tar.gz"

mkdir -p "$BACKUP_ROOT"
rm -rf "$PUBLISH_DIR"

echo "Installing frontend dependencies..."
npm install --prefix "$ROOT_DIR/RotorBase"

echo "Publishing RotorBase..."
dotnet publish "$ROOT_DIR/RotorBase/RotorBase.csproj" -c Release -o "$PUBLISH_DIR"

echo "Backing up current app to $backup_file..."
tar -C "$(dirname "$APP_DIR")" -czf "$backup_file" "$(basename "$APP_DIR")"
chmod 600 "$backup_file"

echo "Deploying published files..."
systemctl stop "$SERVICE_NAME"
rsync -az --delete \
  --exclude 'appsettings*.json' \
  "$PUBLISH_DIR/" "$APP_DIR/"
systemctl start "$SERVICE_NAME"

"$ROOT_DIR/scripts/healthcheck.sh"

echo "Deploy complete."
