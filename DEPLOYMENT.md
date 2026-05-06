# Production Deployment

RotorBase runs on the production host behind nginx and systemd.

- Repo checkout: `/var/www/RotorBase-public`
- Published app: `/opt/rotorbase/app`
- Service: `rotorbase.service`
- Public URL: `https://boostedrotary.com`
- Backups: `/var/backups/rotorbase`

## Secrets

Runtime secrets should live only in `/opt/rotorbase/app/appsettings.Production.json` with root-only permissions.
The default `/opt/rotorbase/app/appsettings.json` should contain placeholders only. Do not commit `appsettings.Production.json`.

## Deploy

```bash
cd /var/www/RotorBase-public
git pull --ff-only
scripts/deploy.sh
```

The deploy script installs frontend dependencies, publishes the .NET app, backs up the current published app, syncs new files while excluding `appsettings*.json`, restarts `rotorbase.service`, and runs health checks.

## Health Check

```bash
cd /var/www/RotorBase-public
scripts/healthcheck.sh
```

Expected output:

```text
rotorbase is active; local=200 public=200
```

## Rollback

```bash
cd /var/www/RotorBase-public
scripts/rollback.sh /var/backups/rotorbase/app-YYYYMMDDTHHMMSSZ.tar.gz
```

## TLS Renewal

```bash
certbot renew --dry-run --cert-name boostedrotary.com --nginx --non-interactive --no-random-sleep
```
