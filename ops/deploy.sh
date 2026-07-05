#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_root
load_config

TAG="${1:-}"
[[ "$TAG" =~ ^n45-v[0-9]{4}\.[0-9]{2}\.[0-9]+$ ]] \
    || die "Usage: $0 n45-vYYYY.MM.N"

for command in git rsync curl php mariadb mariadb-dump gzip tar flock sudo; do
    require_command "$command"
done

[[ -d "$REPO_DIR/.git" ]] || die "Git repository not found: $REPO_DIR"
[[ -f "$CONFIG_PHP" ]] || die "Shared config missing: $CONFIG_PHP"
[[ -d "$UPLOADS_DIR" ]] || die "Shared uploads missing: $UPLOADS_DIR"
[[ -d "$MAINTENANCE_DIR" ]] || die "Maintenance directory missing: $MAINTENANCE_DIR"

install -d -m 0755 "$RELEASES_DIR" "$BACKUPS_DIR"

exec 9>"$APP_BASE/.deploy.lock"
flock -n 9 || die "Another deployment or rollback is already running."

OLD_RELEASE="$(current_release_path)"
[[ "$OLD_RELEASE" != "$(readlink -f "$MAINTENANCE_DIR")" ]] || die "The site currently points to maintenance mode. Resolve the prior deployment before continuing."
NEW_RELEASE="$RELEASES_DIR/$TAG"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="$BACKUPS_DIR/$TAG-$STAMP"
DB_DEFAULTS="$(mktemp)"
DB_NAME=""
DEPLOY_SUCCEEDED=false
DB_BACKUP_CREATED=false

cleanup() {
    rm -f "$DB_DEFAULTS"
}
trap cleanup EXIT

rollback_on_error() {
    local exit_code=$?
    trap - ERR

    log "Deployment failed with exit code $exit_code."

    if [[ -d "$MAINTENANCE_DIR" ]]; then
        atomic_link "$MAINTENANCE_DIR" "$CURRENT_LINK"
    fi

    if [[ "$DB_BACKUP_CREATED" == true && -f "$BACKUP_DIR/database.sql.gz" ]]; then
        log "Restoring database from $BACKUP_DIR/database.sql.gz"
        gzip -dc "$BACKUP_DIR/database.sql.gz" \
            | mariadb --defaults-extra-file="$DB_DEFAULTS" "$DB_NAME"
    else
        log "No database backup was available to restore."
    fi

    if [[ -n "$OLD_RELEASE" && -d "$OLD_RELEASE" ]]; then
        atomic_link "$OLD_RELEASE" "$CURRENT_LINK"
        log "Restored prior release: $OLD_RELEASE"
    fi

    exit "$exit_code"
}
trap rollback_on_error ERR

log "Fetching release tags."
git -C "$REPO_DIR" fetch origin --tags --prune

git -C "$REPO_DIR" rev-parse -q --verify "refs/tags/$TAG^{commit}" >/dev/null \
    || die "Tag does not exist: $TAG"

git -C "$REPO_DIR" merge-base --is-ancestor "$TAG^{commit}" origin/master \
    || die "Tag $TAG is not contained in origin/master."

if [[ -e "$NEW_RELEASE" ]]; then
    die "Release directory already exists: $NEW_RELEASE"
fi

log "Creating immutable release worktree."
git -C "$REPO_DIR" worktree add --detach "$NEW_RELEASE" "$TAG"

rm -f "$NEW_RELEASE/config.php"
rm -rf "$NEW_RELEASE/uploads"
ln -s "$CONFIG_PHP" "$NEW_RELEASE/config.php"
ln -s "$UPLOADS_DIR" "$NEW_RELEASE/uploads"

chown -R root:"$WEB_GROUP" "$NEW_RELEASE"
chmod -R g+rX,o-rwx "$NEW_RELEASE"
chown -h "$WEB_USER:$WEB_GROUP" "$NEW_RELEASE/config.php" "$NEW_RELEASE/uploads"

log "Validating PHP syntax in release."
find "$NEW_RELEASE" \
    -path "$NEW_RELEASE/uploads" -prune -o \
    -path "$NEW_RELEASE/.git" -prune -o \
    -type f -name '*.php' -print0 \
    | xargs -0 -n1 php -l >/dev/null

install -d -m 0750 "$BACKUP_DIR"
make_db_defaults_file "$DB_DEFAULTS"
DB_NAME="$(database_name)"
[[ -n "$DB_NAME" ]] || die "Unable to determine database name."

log "Creating transaction-consistent MariaDB backup."
mariadb-dump \
    --defaults-extra-file="$DB_DEFAULTS" \
    --single-transaction \
    --quick \
    --routines \
    --triggers \
    --events \
    --hex-blob \
    "$DB_NAME" \
    | gzip -9 > "$BACKUP_DIR/database.sql.gz"
DB_BACKUP_CREATED=true

cp -a "$CONFIG_PHP" "$BACKUP_DIR/config.php"

if [[ "$BACKUP_UPLOADS" == "true" ]]; then
    log "Archiving uploads."
    tar \
        --exclude='uploads/tmp/*' \
        -C "$SHARED_DIR" \
        -czf "$BACKUP_DIR/uploads.tar.gz" \
        uploads
fi

printf '%s\n' "$OLD_RELEASE" > "$BACKUP_DIR/previous-release.txt"
printf '%s\n' "$TAG" > "$BACKUP_DIR/target-release.txt"
git -C "$REPO_DIR" rev-parse "$TAG^{commit}" > "$BACKUP_DIR/commit.txt"

log "Enabling maintenance page."
atomic_link "$MAINTENANCE_DIR" "$CURRENT_LINK"

log "Running upstream ITFlow database updates as the root-owned file owner."
php "$NEW_RELEASE/scripts/update_cli.php" --update_db

if [[ -f "$NEW_RELEASE/ops/run-n45-migrations.php" ]]; then
    log "Running N45 database migrations."
    php "$NEW_RELEASE/ops/run-n45-migrations.php" "$NEW_RELEASE"
fi

log "Verifying database version before activation."
php "$NEW_RELEASE/ops/verify-db-version.php" "$NEW_RELEASE"

log "Activating release."
atomic_link "$NEW_RELEASE" "$CURRENT_LINK"

log "Running smoke tests."
"$SCRIPT_DIR/smoke-test.sh" "$NEW_RELEASE"

DEPLOY_SUCCEEDED=true
trap - ERR

log "Deployment successful: $TAG"
log "Backup: $BACKUP_DIR"

find "$BACKUPS_DIR" \
    -mindepth 1 -maxdepth 1 -type d \
    -mtime "+$BACKUP_RETENTION_DAYS" \
    -print -exec rm -rf {} +

# Keep the current release and the five most recently modified older releases.
mapfile -t OLD_RELEASES < <(
    find "$RELEASES_DIR" -mindepth 1 -maxdepth 1 -type d \
        ! -path "$NEW_RELEASE" \
        ! -path "$MAINTENANCE_DIR" \
        -printf '%T@ %p\n' \
        | sort -nr \
        | awk 'NR > 5 {sub(/^[^ ]+ /, ""); print}'
)

for old in "${OLD_RELEASES[@]:-}"; do
    [[ -n "$old" ]] || continue
    if [[ "$old" != "$OLD_RELEASE" ]]; then
        git -C "$REPO_DIR" worktree remove --force "$old" 2>/dev/null || rm -rf "$old"
    fi
done
