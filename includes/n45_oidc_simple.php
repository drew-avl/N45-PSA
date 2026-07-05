<?php
/**
 * N45 simple OpenID Connect helpers for ITFlow.
 * Working-pattern Authentik OIDC with optional first-login technician auto-provisioning.
 */

function n45_oidc_log($message, $context = [])
{
    $safe = [];
    foreach ($context as $key => $value) {
        $k = (string)$key;
        if (
            stripos($k, 'token') !== false ||
            stripos($k, 'secret') !== false ||
            stripos($k, 'password') !== false ||
            stripos($k, 'ciphertext') !== false ||
            stripos($k, 'code') !== false
        ) {
            $safe[$key] = '[redacted length=' . strlen((string)$value) . ']';
        } else {
            $safe[$key] = $value;
        }
    }

    error_log('N45 SIMPLE OIDC: ' . $message . ' ' . json_encode($safe));
}

function n45_oidc_fail($message, $status = 400, $context = [])
{
    n45_oidc_log('FAIL ' . $message, $context);
    http_response_code($status);
    echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    exit();
}

function n45_oidc_settings($mysqli)
{
    $result = mysqli_query($mysqli, "
        SELECT *
        FROM settings
        WHERE company_id = 1
        LIMIT 1
    ");

    if (!$result) {
        return null;
    }

    $row = mysqli_fetch_assoc($result);
    if (!$row || intval($row['config_oidc_authentik_enabled'] ?? 0) !== 1) {
        return null;
    }

    $issuer = trim((string)($row['config_oidc_authentik_issuer'] ?? ''));

    if ($issuer !== '' && !str_contains($issuer, '/.well-known/openid-configuration')) {
        $issuer = rtrim($issuer, '/') . '/';
        $discovery_url = $issuer . '.well-known/openid-configuration';
    } else {
        $discovery_url = $issuer;
    }

    return [
        'issuer' => $issuer,
        'discovery_url' => $discovery_url,
        'client_id' => trim((string)($row['config_oidc_authentik_client_id'] ?? '')),
        'client_secret' => trim((string)($row['config_oidc_authentik_client_secret'] ?? '')),
        'scopes' => trim((string)($row['config_oidc_authentik_scopes'] ?? 'openid email profile')) ?: 'openid email profile',
        'email_claim' => trim((string)($row['config_oidc_authentik_email_claim'] ?? 'email')) ?: 'email',
        'name_claim' => trim((string)($row['config_oidc_authentik_name_claim'] ?? 'name')) ?: 'name',
        'encryption_key_claim' => trim((string)($row['config_oidc_authentik_encryption_key_claim'] ?? 'encryption_key')) ?: 'encryption_key',
        'bypass_local_mfa' => intval($row['config_oidc_authentik_bypass_local_mfa'] ?? 1),
        'auto_create_enabled' => intval($row['config_oidc_authentik_auto_create_enabled'] ?? 0),
        'auto_create_domain' => trim((string)($row['config_oidc_authentik_auto_create_domain'] ?? 'n45tech.com')) ?: 'n45tech.com',
        'auto_create_role_id' => intval($row['config_oidc_authentik_auto_create_role_id'] ?? 0),
        'auto_create_force_mfa' => intval($row['config_oidc_authentik_auto_create_force_mfa'] ?? 1),
        'provisioning_ciphertext' => (string)($row['config_oidc_authentik_provisioning_ciphertext'] ?? ''),
    ];
}

function n45_oidc_http_json($url, $method = 'GET', $post_fields = null, $headers = [])
{
    $method = strtoupper($method);
    n45_oidc_log('HTTP request', ['url' => $url, 'method' => $method]);

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, is_array($post_fields) ? http_build_query($post_fields) : $post_fields);
        }

        $body = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $status = intval(curl_getinfo($ch, CURLINFO_HTTP_CODE));
        curl_close($ch);

        if ($body === false || $errno) {
            n45_oidc_fail('OIDC HTTP request failed: ' . $error, 502, ['url' => $url, 'curl_errno' => $errno]);
        }

        n45_oidc_log('HTTP response', ['url' => $url, 'status' => $status, 'length' => strlen((string)$body)]);

        if ($status < 200 || $status >= 300) {
            n45_oidc_fail('OIDC provider returned HTTP ' . $status, 502, ['url' => $url, 'body' => substr((string)$body, 0, 500)]);
        }

        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            n45_oidc_fail('OIDC provider returned invalid JSON', 502, ['url' => $url, 'body' => substr((string)$body, 0, 500)]);
        }

        return $decoded;
    }

    $opts = [
        'http' => [
            'method' => $method,
            'timeout' => 20,
            'ignore_errors' => true,
            'header' => implode("\r\n", $headers),
        ],
    ];

    if ($method === 'POST') {
        $opts['http']['content'] = is_array($post_fields) ? http_build_query($post_fields) : (string)$post_fields;
    }

    $context = stream_context_create($opts);
    $body = file_get_contents($url, false, $context);

    if ($body === false) {
        n45_oidc_fail('OIDC HTTP request failed via stream wrapper', 502, ['url' => $url]);
    }

    $decoded = json_decode($body, true);
    if (!is_array($decoded)) {
        n45_oidc_fail('OIDC provider returned invalid JSON', 502, ['url' => $url, 'body' => substr((string)$body, 0, 500)]);
    }

    return $decoded;
}

function n45_oidc_decode_jwt_payload($jwt)
{
    $parts = explode('.', (string)$jwt);
    if (count($parts) < 2) {
        return null;
    }

    $payload = strtr($parts[1], '-_', '+/');
    $payload .= str_repeat('=', (4 - strlen($payload) % 4) % 4);
    $json = base64_decode($payload, true);

    if ($json === false) {
        return null;
    }

    $decoded = json_decode($json, true);
    return is_array($decoded) ? $decoded : null;
}

function n45_oidc_claim($claims, $name)
{
    if (!$name || !is_array($claims)) {
        return null;
    }

    if (array_key_exists($name, $claims)) {
        return $claims[$name];
    }

    if (str_contains($name, '.')) {
        $cursor = $claims;
        foreach (explode('.', $name) as $part) {
            if (!is_array($cursor) || !array_key_exists($part, $cursor)) {
                return null;
            }
            $cursor = $cursor[$part];
        }
        return $cursor;
    }

    return null;
}

function n45_oidc_current_url_base()
{
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    return ($https ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'];
}

function n45_oidc_callback_url()
{
    return n45_oidc_current_url_base() . '/agent/openid_callback.php';
}

function n45_oidc_table_has_column($mysqli, $table, $column)
{
    if (!preg_match('/^[A-Za-z0-9_]+$/', $table) || !preg_match('/^[A-Za-z0-9_]+$/', $column)) {
        return false;
    }

    $columnSql = mysqli_real_escape_string($mysqli, $column);
    $result = mysqli_query($mysqli, "SHOW COLUMNS FROM `$table` LIKE '$columnSql'");
    return $result && mysqli_num_rows($result) > 0;
}

function n45_oidc_email_domain_allowed($email, $domainList)
{
    $email = strtolower(trim((string)$email));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }

    $domain = substr(strrchr($email, '@'), 1);
    $configured = preg_split('/[\s,;]+/', strtolower((string)$domainList), -1, PREG_SPLIT_NO_EMPTY);

    foreach ($configured as $allowed) {
        $allowed = ltrim(trim($allowed), '@');
        if ($allowed !== '' && hash_equals($allowed, $domain)) {
            return true;
        }
    }

    return false;
}

function n45_oidc_display_name($nameClaim, $email)
{
    if (is_array($nameClaim)) {
        $nameClaim = '';
    }

    $name = trim((string)$nameClaim);
    if ($name === '') {
        $name = explode('@', (string)$email)[0];
    }

    return sanitizeInput($name);
}

function n45_oidc_get_provisioning_secret()
{
    $secret = getenv('ITFLOW_OIDC_PROVISIONING_SECRET');
    if (!$secret && !empty($_SERVER['ITFLOW_OIDC_PROVISIONING_SECRET'])) {
        $secret = $_SERVER['ITFLOW_OIDC_PROVISIONING_SECRET'];
    }

    if (!$secret) {
        $path = getenv('ITFLOW_OIDC_PROVISIONING_SECRET_FILE') ?: '/etc/itflow/oidc_provisioning_secret';
        if (is_readable($path)) {
            $secret = trim((string)file_get_contents($path));
        }
    }

    return trim((string)$secret);
}

function n45_oidc_get_provisioning_site_key($openid_config)
{
    if (empty($openid_config['provisioning_ciphertext'])) {
        n45_oidc_fail('OIDC auto-provisioning is enabled, but provisioning ciphertext is not initialized.', 500);
    }

    $secret = n45_oidc_get_provisioning_secret();
    if ($secret === '') {
        n45_oidc_fail('OIDC auto-provisioning is enabled, but ITFLOW_OIDC_PROVISIONING_SECRET is not available to PHP.', 500);
    }

    $siteKey = decryptUserSpecificKey($openid_config['provisioning_ciphertext'], $secret);
    if (!$siteKey) {
        n45_oidc_fail('OIDC auto-provisioning could not decrypt the provisioning vault wrapper.', 500);
    }

    return $siteKey;
}

function n45_oidc_fetch_user_by_email($mysqli, $email, $onlyActiveTechnician = true)
{
    $emailSql = mysqli_real_escape_string($mysqli, strtolower(trim((string)$email)));
    $where = "LOWER(user_email) = '$emailSql'";
    if ($onlyActiveTechnician) {
        $where .= " AND user_type = 1 AND user_status = 1 AND user_archived_at IS NULL";
    }

    $result = mysqli_query($mysqli, "
        SELECT
            user_id,
            user_name,
            user_email,
            user_status,
            user_archived_at,
            user_type,
            user_token,
            user_specific_encryption_ciphertext
        FROM users
        WHERE $where
        LIMIT 1
    ");

    if (!$result) {
        n45_oidc_fail('ITFlow user lookup failed.', 500, ['mysqli_error' => mysqli_error($mysqli)]);
    }

    return mysqli_fetch_assoc($result);
}

function n45_oidc_insert_dynamic($mysqli, $table, $values)
{
    if (!preg_match('/^[A-Za-z0-9_]+$/', $table)) {
        n45_oidc_fail('Invalid table name for dynamic insert.', 500);
    }

    $cols = [];
    $vals = [];

    foreach ($values as $column => $value) {
        if (!n45_oidc_table_has_column($mysqli, $table, $column)) {
            continue;
        }
        $cols[] = '`' . $column . '`';
        if ($value === null) {
            $vals[] = 'NULL';
        } elseif (is_int($value) || is_float($value)) {
            $vals[] = (string)$value;
        } else {
            $vals[] = "'" . mysqli_real_escape_string($mysqli, (string)$value) . "'";
        }
    }

    if (!$cols) {
        n45_oidc_fail('No valid columns for dynamic insert.', 500, ['table' => $table]);
    }

    $sql = "INSERT INTO `$table` (" . implode(',', $cols) . ") VALUES (" . implode(',', $vals) . ")";
    $ok = mysqli_query($mysqli, $sql);
    if (!$ok) {
        n45_oidc_fail('Dynamic insert failed.', 500, ['table' => $table, 'mysqli_error' => mysqli_error($mysqli)]);
    }

    return intval(mysqli_insert_id($mysqli));
}

function n45_oidc_auto_provision_user($mysqli, $openid_config, $email, $displayName, $ssoDecryptionKey)
{
    global $session_user_id;

    if (intval($openid_config['auto_create_enabled'] ?? 0) !== 1) {
        return null;
    }

    if (!n45_oidc_email_domain_allowed($email, $openid_config['auto_create_domain'] ?? '')) {
        n45_oidc_fail('OIDC auto-provisioning denied this email domain.', 403, [
            'email' => $email,
            'allowed_domains' => $openid_config['auto_create_domain'] ?? '',
        ]);
    }

    $roleId = intval($openid_config['auto_create_role_id'] ?? 0);
    if ($roleId <= 0) {
        n45_oidc_fail('OIDC auto-provisioning is enabled, but no default ITFlow role ID is configured.', 500, ['email' => $email]);
    }

    $existingAny = n45_oidc_fetch_user_by_email($mysqli, $email, false);
    if ($existingAny) {
        n45_oidc_fail('An ITFlow user with this email already exists, but it is not an active technician account.', 403, [
            'email' => $email,
            'user_id' => intval($existingAny['user_id']),
            'user_type' => intval($existingAny['user_type']),
            'user_status' => intval($existingAny['user_status']),
        ]);
    }

    $siteKey = n45_oidc_get_provisioning_site_key($openid_config);
    $userCiphertext = setupFirstUserSpecificKey((string)$ssoDecryptionKey, $siteKey);
    if (!$userCiphertext) {
        n45_oidc_fail('Failed to create OIDC user vault wrapper.', 500, ['email' => $email]);
    }

    $randomLocalPassword = bin2hex(random_bytes(32));
    $passwordHash = password_hash($randomLocalPassword, PASSWORD_DEFAULT);
    $displayName = n45_oidc_display_name($displayName, $email);
    $now = date('Y-m-d H:i:s');

    $userId = n45_oidc_insert_dynamic($mysqli, 'users', [
        'user_name' => $displayName,
        'user_email' => strtolower(trim((string)$email)),
        'user_password' => $passwordHash,
        'user_specific_encryption_ciphertext' => $userCiphertext,
        'user_role_id' => $roleId,
        'user_type' => 1,
        'user_status' => 1,
        'user_created_at' => $now,
        'user_updated_at' => $now,
    ]);

    if ($userId <= 0) {
        n45_oidc_fail('OIDC auto-provisioning created no user ID.', 500, ['email' => $email]);
    }

    if (mysqli_query($mysqli, "SHOW TABLES LIKE 'user_settings'") && n45_oidc_table_has_column($mysqli, 'user_settings', 'user_id')) {
        $settingsValues = ['user_id' => $userId];
        if (n45_oidc_table_has_column($mysqli, 'user_settings', 'user_config_force_mfa')) {
            $settingsValues['user_config_force_mfa'] = intval($openid_config['auto_create_force_mfa'] ?? 1);
        }
        n45_oidc_insert_dynamic($mysqli, 'user_settings', $settingsValues);
    }

    $uploadDir = dirname(__DIR__) . "/uploads/users/$userId";
    if (!is_dir($uploadDir)) {
        @mkdir($uploadDir, 0755, true);
    }

    if (function_exists('logAction')) {
        logAction('User', 'Create', "Auto-provisioned Authentik OIDC technician user $displayName <$email>", 0, intval($session_user_id ?? 0));
    }

    n45_oidc_log('Auto-provisioned ITFlow technician user', ['email' => $email, 'user_id' => $userId, 'role_id' => $roleId]);

    return n45_oidc_fetch_user_by_email($mysqli, $email, true);
}
