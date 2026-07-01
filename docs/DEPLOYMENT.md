# N45 PSA Production Deployment

These instructions match the release layout created for the N45 production server:

- App base: `/var/www/n45-psa`
- Shared config: `/var/www/n45-psa/shared/config.php`
- Shared uploads: `/var/www/n45-psa/shared/uploads`
- Current web root symlink: `/var/www/n45-psa/current`
- Bare deployment repo: `/opt/n45-psa-repo`
- Release config: `/etc/n45-itflow-release.conf`

## Server Prerequisites

Install the runtime tools used by `ops/deploy.sh`:

```bash
sudo apt-get update
sudo apt-get install -y git rsync curl php-cli php-mysqli mariadb-client gzip tar util-linux sudo
```

Confirm `/etc/n45-itflow-release.conf` exists and matches the server:

```bash
APP_BASE=/var/www/n45-psa
REPO_DIR=/opt/n45-psa-repo
APP_URL=https://psa.n45tech.com
WEB_USER=www-data
WEB_GROUP=www-data
BACKUP_RETENTION_DAYS=30
BACKUP_UPLOADS=true
```

Apache or Nginx should serve `/var/www/n45-psa/current`.

## Recover From A Failed Deployment

If the failed release left the site in maintenance mode, `deploy.sh` will refuse to continue until the current symlink is restored to a real release.

Check the current target:

```bash
sudo readlink -f /var/www/n45-psa/current
```

If it points at `/var/www/n45-psa/shared/maintenance`, restore the prior release and database from the failed deployment backup:

```bash
sudo ls -1dt /var/www/n45-psa/backups/*
sudo /opt/n45-psa-repo/ops/rollback.sh n45-v2026.06.1 /var/www/n45-psa/backups/<failed-backup-dir>/database.sql.gz
```

Use the previous good tag in place of `n45-v2026.06.1` if production was on a different release.

## Publish A Fixed Release

After this fix is merged to `master`, create a new tag. Do not reuse `n45-v2026.06.2`; the production deploy should use the next tag.

```bash
git checkout master
git pull origin master
git tag n45-v2026.06.3
git push origin n45-v2026.06.3
```

Wait for the GitHub release workflow to pass and publish the release.

## Deploy

On the production server:

```bash
sudo git -C /opt/n45-psa-repo fetch origin --tags --prune
sudo N45_RELEASE_CONFIG=/etc/n45-itflow-release.conf /opt/n45-psa-repo/ops/deploy.sh n45-v2026.06.3
```

The deploy script will:

1. Create a release worktree under `/var/www/n45-psa/releases`.
2. Link shared `config.php` and `uploads`.
3. Lint PHP files.
4. Back up MariaDB, config, and uploads.
5. Switch to maintenance mode.
6. Run upstream ITFlow database updates.
7. Run N45 migrations.
8. Verify the database version.
9. Activate the new release and run smoke tests.

## Verify After Deployment

Run these checks on the server:

```bash
sudo /opt/n45-psa-repo/ops/smoke-test.sh /var/www/n45-psa/current
curl -I https://psa.n45tech.com/login.php
```

Confirm the N45 migrations and SSO master key:

```bash
sudo php /var/www/n45-psa/current/ops/run-n45-migrations.php /var/www/n45-psa/current
sudo php <<'PHP'
<?php
require "/var/www/n45-psa/shared/config.php";

$migrations = mysqli_query($mysqli, "SELECT migration, applied_at FROM n45_schema_migrations ORDER BY migration");
while ($row = mysqli_fetch_assoc($migrations)) {
    echo $row['migration'] . " " . $row['applied_at'] . PHP_EOL;
}

$settings = mysqli_query($mysqli, "SELECT company_id, config_site_encryption_master_key <> '' AS has_sso_master_key FROM settings");
while ($row = mysqli_fetch_assoc($settings)) {
    echo "company_id=" . $row['company_id'] . " has_sso_master_key=" . $row['has_sso_master_key'] . PHP_EOL;
}
PHP
```

Expected N45 migration entries include:

- `20260628_000_prepare_sso_prerequisites.sql`
- `20260628_001_add_sso_schema.sql`

`has_sso_master_key` should be `1` for company `1`.

## Manual Rollback

If a deployment fails after activation, use the backup path printed by `deploy.sh`:

```bash
sudo /opt/n45-psa-repo/ops/rollback.sh <previous-tag> /var/www/n45-psa/backups/<backup-dir>/database.sql.gz
```

The rollback restores the database, switches `/var/www/n45-psa/current` back to the target release, and runs smoke tests.
