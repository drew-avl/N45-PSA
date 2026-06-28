#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

load_config

RELEASE_DIR="${1:-$(current_release_path)}"
[[ -n "$RELEASE_DIR" && -d "$RELEASE_DIR" ]] || die "Release directory not found."

[[ -L "$RELEASE_DIR/config.php" ]] || die "config.php is not a symlink."
[[ -L "$RELEASE_DIR/uploads" ]] || die "uploads is not a symlink."
[[ -f "$RELEASE_DIR/login.php" ]] || die "login.php is missing."
[[ -f "$RELEASE_DIR/includes/database_version.php" ]] || die "Database version file is missing."

run_as_web_user php "$RELEASE_DIR/ops/verify-db-version.php" "$RELEASE_DIR"

HTTP_CODE="$(
    curl \
        --silent \
        --show-error \
        --location \
        --retry 5 \
        --retry-delay 2 \
        --connect-timeout 10 \
        --max-time 30 \
        --output /tmp/n45-itflow-smoke-body.$$ \
        --write-out '%{http_code}' \
        "$APP_URL/login.php"
)"
trap 'rm -f /tmp/n45-itflow-smoke-body.$$' EXIT

[[ "$HTTP_CODE" == "200" ]] || die "Unexpected HTTP status from login page: $HTTP_CODE"

grep -Eqi 'login|sign in|ITFlow|N45' /tmp/n45-itflow-smoke-body.$$ \
    || die "Login page response did not contain an expected marker."

printf 'Smoke tests passed for %s\n' "$RELEASE_DIR"
