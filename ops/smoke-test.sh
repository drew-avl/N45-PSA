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

LOGIN_HEADERS="$(mktemp /tmp/n45-login-headers.XXXXXX)"
LOCAL_BODY="$(mktemp /tmp/n45-local-login-body.XXXXXX)"
CLIENT_BODY="$(mktemp /tmp/n45-client-login-body.XXXXXX)"
trap 'rm -f "$LOGIN_HEADERS" "$LOCAL_BODY" "$CLIENT_BODY"' EXIT

HTTP_CODE="$(
    curl \
        --silent \
        --show-error \
        --retry 5 \
        --retry-delay 2 \
        --connect-timeout 10 \
        --max-time 30 \
        --output /dev/null \
        --dump-header "$LOGIN_HEADERS" \
        --write-out '%{http_code}' \
        "$APP_URL/login.php"
)"

[[ "$HTTP_CODE" == "302" ]] || die "Unexpected HTTP status from technician login redirect: $HTTP_CODE"
grep -Eqi '^Location: .*/agent/openid_login\.php' "$LOGIN_HEADERS" \
    || die "Technician login did not redirect to /agent/openid_login.php."

LOCAL_HTTP_CODE="$(
    curl \
        --silent \
        --show-error \
        --retry 5 \
        --retry-delay 2 \
        --connect-timeout 10 \
        --max-time 30 \
        --output "$LOCAL_BODY" \
        --write-out '%{http_code}' \
        "$APP_URL/login.php?source=local"
)"

[[ "$LOCAL_HTTP_CODE" == "200" ]] || die "Unexpected HTTP status from local technician login page: $LOCAL_HTTP_CODE"
grep -Eqi 'Sign In' "$LOCAL_BODY" \
    || die "Local technician login page response did not contain the sign-in button."
grep -Eqi 'Email' "$LOCAL_BODY" \
    || die "Local technician login page response did not contain the email field."
grep -Eqi 'Password' "$LOCAL_BODY" \
    || die "Local technician login page response did not contain the password field."
grep -Eqi 'Sign in with SSO' "$LOCAL_BODY" \
    || die "Local technician login page response did not contain the SSO login link."
! grep -Eqi 'Microsoft Entra|Forgot password|Client Portal' "$LOCAL_BODY" \
    || die "Local technician login page exposed client authentication controls."

CLIENT_HTTP_CODE="$(
    curl \
        --silent \
        --show-error \
        --location \
        --retry 5 \
        --retry-delay 2 \
        --connect-timeout 10 \
        --max-time 30 \
        --output "$CLIENT_BODY" \
        --write-out '%{http_code}' \
        "$APP_URL/client/"
)"

[[ "$CLIENT_HTTP_CODE" == "200" ]] || die "Unexpected HTTP status from client login flow: $CLIENT_HTTP_CODE"
grep -Eqi 'Client Portal' "$CLIENT_BODY" \
    || die "Client login page response did not contain the client portal marker."
grep -Eqi 'Email' "$CLIENT_BODY" \
    || die "Client login page response did not contain the email field."
grep -Eqi 'Password' "$CLIENT_BODY" \
    || die "Client login page response did not contain the password field."
grep -Eqi 'Sign In' "$CLIENT_BODY" \
    || die "Client login page response did not contain the sign-in button."

printf 'Smoke tests passed for %s\n' "$RELEASE_DIR"
