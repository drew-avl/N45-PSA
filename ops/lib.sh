#!/usr/bin/env bash

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

require_root() {
    [[ $EUID -eq 0 ]] || die "Run this command as root."
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

load_config() {
    local config_file="${N45_RELEASE_CONFIG:-/etc/n45-itflow-release.conf}"
    [[ -f "$config_file" ]] || die "Configuration file not found: $config_file"

    # shellcheck disable=SC1090
    source "$config_file"

    : "${APP_BASE:?APP_BASE is required}"
    : "${REPO_DIR:?REPO_DIR is required}"
    : "${APP_URL:?APP_URL is required}"
    : "${WEB_USER:=www-data}"
    : "${WEB_GROUP:=www-data}"
    : "${BACKUP_RETENTION_DAYS:=30}"
    : "${BACKUP_UPLOADS:=true}"

    RELEASES_DIR="$APP_BASE/releases"
    SHARED_DIR="$APP_BASE/shared"
    BACKUPS_DIR="$APP_BASE/backups"
    CURRENT_LINK="$APP_BASE/current"
    MAINTENANCE_DIR="$SHARED_DIR/maintenance"
    CONFIG_PHP="$SHARED_DIR/config.php"
    UPLOADS_DIR="$SHARED_DIR/uploads"
}

atomic_link() {
    local target="$1"
    local link="$2"
    ln -sfn "$target" "${link}.new"
    mv -Tf "${link}.new" "$link"
}

current_release_path() {
    readlink -f "$CURRENT_LINK" 2>/dev/null || true
}

make_db_defaults_file() {
    local output_file="$1"
    php -r '
        $config = $argv[1];
        $output = $argv[2];
        require $config;
        $escape = static function ($value): string {
            return str_replace(
                ["\\", "\"", "\n", "\r"],
                ["\\\\", "\\\"", "", ""],
                (string) $value
            );
        };
        $data = "[client]\n"
            . "host=\"" . $escape($dbhost) . "\"\n"
            . "user=\"" . $escape($dbusername) . "\"\n"
            . "password=\"" . $escape($dbpassword) . "\"\n";
        if (file_put_contents($output, $data, LOCK_EX) === false) {
            fwrite(STDERR, "Unable to create MariaDB defaults file.\n");
            exit(1);
        }
        chmod($output, 0600);
    ' "$CONFIG_PHP" "$output_file"
}

database_name() {
    php -r 'require $argv[1]; echo $database;' "$CONFIG_PHP"
}

run_as_web_user() {
    sudo -u "$WEB_USER" -- "$@"
}
