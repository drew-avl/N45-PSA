#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_root
load_config

TARGET_TAG="${1:-}"
BACKUP_FILE="${2:-}"

[[ -n "$TARGET_TAG" && -n "$BACKUP_FILE" ]] \
    || die "Usage: $0 TARGET_RELEASE_TAG /path/to/database.sql.gz"

TARGET_RELEASE="$RELEASES_DIR/$TARGET_TAG"

for command in php mariadb gzip flock sudo curl; do
    require_command "$command"
done

[[ -d "$TARGET_RELEASE" ]] || die "Target release not found: $TARGET_RELEASE"
[[ -f "$BACKUP_FILE" ]] || die "Database backup not found: $BACKUP_FILE"
[[ -f "$CONFIG_PHP" ]] || die "Shared config missing: $CONFIG_PHP"

exec 9>"$APP_BASE/.deploy.lock"
flock -n 9 || die "Another deployment or rollback is already running."

DB_DEFAULTS="$(mktemp)"
trap 'rm -f "$DB_DEFAULTS"' EXIT

make_db_defaults_file "$DB_DEFAULTS"
DB_NAME="$(database_name)"

log "Enabling maintenance page."
atomic_link "$MAINTENANCE_DIR" "$CURRENT_LINK"

log "Restoring database."
gzip -dc "$BACKUP_FILE" \
    | mariadb --defaults-extra-file="$DB_DEFAULTS" "$DB_NAME"

log "Activating release: $TARGET_TAG"
atomic_link "$TARGET_RELEASE" "$CURRENT_LINK"

log "Running smoke tests."
"$SCRIPT_DIR/smoke-test.sh" "$TARGET_RELEASE"

log "Rollback completed successfully."
