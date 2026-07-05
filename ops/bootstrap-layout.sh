#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_DIR="${1:-}"
APP_BASE="${2:-/var/www/n45-psa}"
WEB_USER="${WEB_USER:-www-data}"
WEB_GROUP="${WEB_GROUP:-www-data}"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || die "Run this script as root."
[[ -n "$SOURCE_DIR" ]] || die "Usage: $0 /path/to/current/itflow [/var/www/n45-psa]"
[[ -d "$SOURCE_DIR" ]] || die "Source directory does not exist: $SOURCE_DIR"
[[ -f "$SOURCE_DIR/config.php" ]] || die "Missing $SOURCE_DIR/config.php"
[[ -d "$SOURCE_DIR/uploads" ]] || die "Missing $SOURCE_DIR/uploads"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BOOTSTRAP_RELEASE="$APP_BASE/releases/bootstrap-$STAMP"

install -d -m 0755 "$APP_BASE/releases" "$APP_BASE/shared" "$APP_BASE/backups"
install -d -m 0755 "$BOOTSTRAP_RELEASE"
install -d -m 0755 "$APP_BASE/shared/maintenance"

printf 'Copying application files...\n'
rsync -a \
    --exclude='.git/' \
    --exclude='config.php' \
    --exclude='uploads/' \
    "$SOURCE_DIR/" "$BOOTSTRAP_RELEASE/"

printf 'Copying shared configuration and uploads...\n'
install -m 0640 -o "$WEB_USER" -g "$WEB_GROUP" \
    "$SOURCE_DIR/config.php" "$APP_BASE/shared/config.php"

rsync -a "$SOURCE_DIR/uploads/" "$APP_BASE/shared/uploads/"
chown -R "$WEB_USER:$WEB_GROUP" "$APP_BASE/shared/uploads"

ln -s "$APP_BASE/shared/config.php" "$BOOTSTRAP_RELEASE/config.php"
ln -s "$APP_BASE/shared/uploads" "$BOOTSTRAP_RELEASE/uploads"

cat > "$APP_BASE/shared/maintenance/index.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>N45 PSA Maintenance</title>
  <style>
    body{margin:0;font-family:system-ui,sans-serif;background:#081020;color:#e8f1f7;display:grid;min-height:100vh;place-items:center}
    main{max-width:640px;padding:48px;text-align:center}
    h1{font-size:2rem;margin:0 0 12px}
    p{color:#aebdca;line-height:1.6}
    .mark{color:#2cdcc4;font-weight:700;letter-spacing:.08em}
  </style>
</head>
<body><main><div class="mark">N45</div><h1>Scheduled maintenance</h1><p>The service is being updated. Retry shortly.</p></main></body>
</html>
HTML

atomic_link() {
    local target="$1"
    local link="$2"
    ln -sfn "$target" "${link}.new"
    mv -Tf "${link}.new" "$link"
}

atomic_link "$BOOTSTRAP_RELEASE" "$APP_BASE/current"

chown -R root:root "$APP_BASE/releases"
chown -R "$WEB_USER:$WEB_GROUP" "$APP_BASE/shared"
chmod 0640 "$APP_BASE/shared/config.php"

printf '\nBootstrap layout created successfully.\n'
printf 'Current release: %s\n' "$BOOTSTRAP_RELEASE"
printf 'Next: point Apache DocumentRoot to %s/current and validate before removing the old installation.\n' "$APP_BASE"
