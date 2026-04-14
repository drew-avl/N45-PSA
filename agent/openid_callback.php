<?php
/**
 * OpenID Connect Callback Handler for Agent Portal
 * Processes authorization response and completes authentication
 */

if (!file_exists('../config.php')) {
    header("Location: /setup");
    exit();
}

require_once "../config.php";
require_once "../functions.php";
require_once "../plugins/totp/totp.php";

if (session_status() === PHP_SESSION_NONE) {
    ini_set("session.cookie_httponly", true);
    if ($config_https_only || !isset($config_https_only)) {
        ini_set("session.cookie_secure", true);
    }
    session_start();
}

if (!isset($config_enable_setup) || $config_enable_setup == 1) {
    header("Location: /setup");
    exit();
}

require_once "../includes/inc_set_timezone.php";

$session_ip = sanitizeInput(getIP());
$session_user_agent = sanitizeInput($_SERVER['HTTP_USER_AGENT'] ?? '');

// Get OpenID configuration
$openid_config = getOpenIDConfig($mysqli);

if (!$openid_config) {
    http_response_code(400);
    logSSOAuth($mysqli, 'Callback', 'Failed', null, null, 'OpenID not configured', $session_ip, $session_user_agent);
    exit("OpenID Connect is not configured");
}

// Validate request
if (empty($_GET['code'])) {
    $error = $_GET['error'] ?? 'unknown_error';
    $error_desc = $_GET['error_description'] ?? 'No authorization code received';
    logSSOAuth($mysqli, 'Callback', 'Failed', null, null, "Authorization error: $error - $error_desc", $session_ip, $session_user_agent);
    http_response_code(400);
    exit("Authorization failed: $error - $error_desc");
}

// Validate state to prevent CSRF
if (empty($_GET['state']) || !isset($_SESSION['openid_state']) || $_GET['state'] !== $_SESSION['openid_state']) {
    logSSOAuth($mysqli, 'Callback', 'Failed', null, null, 'Invalid state parameter (CSRF attempt?)', $session_ip, $session_user_agent);
    http_response_code(403);
    exit("Invalid state parameter. This may indicate a CSRF attack.");
}

$auth_code = sanitizeInput($_GET['code']);

// Fetch provider metadata for token endpoint
$metadata = fetchOpenIDMetadata($openid_config['discovery_url']);

if (!$metadata) {
    logSSOAuth($mysqli, 'Token Exchange', 'Failed', null, null, 'Could not fetch provider metadata', $session_ip, $session_user_agent);
    http_response_code(500);
    exit("Failed to fetch OpenID provider metadata");
}

// Callback URL
$callback_url = getBaseUrl() . '/agent/openid_callback.php';

// DEBUG: Log the callback URL being used
error_log("OpenID Callback URL: $callback_url");
error_log("OpenID Token Endpoint: " . $metadata['token_endpoint']);

// Exchange authorization code for token
$token_response = exchangeOpenIDAuthorizationCode(
    $metadata['token_endpoint'],
    $openid_config['client_id'],
    $openid_config['client_secret'],
    $auth_code,
    $callback_url
);

if (!$token_response) {
    logSSOAuth($mysqli, 'Token Exchange', 'Failed', null, null, 'Failed to exchange authorization code', $session_ip, $session_user_agent);
    http_response_code(500);
    exit("Failed to obtain access token from provider");
}

// Get user info
$user_info = null;

if ($metadata['userinfo_endpoint']) {
    $user_info = getOpenIDUserInfo($metadata['userinfo_endpoint'], $token_response['access_token']);
}

// If userinfo endpoint not provided, try to decode ID token
if (!$user_info && !empty($token_response['id_token'])) {
    $id_token_decoded = decodeOpenIDToken($token_response['id_token']);
    if ($id_token_decoded) {
        $user_info = $id_token_decoded;
    }
}

if (!$user_info || empty($user_info['email'])) {
    logSSOAuth($mysqli, 'UserInfo', 'Failed', null, null, 'Could not retrieve user email from provider', $session_ip, $session_user_agent);
    http_response_code(400);
    exit("Could not retrieve user information from provider");
}

$user_email = sanitizeInput($user_info['email']);
$user_name = sanitizeInput($user_info['name'] ?? $user_info['preferred_username'] ?? explode('@', $user_email)[0]);

// Extract decryption key from custom claim
$decryption_key_claim = $openid_config['decryption_key_claim'];
$sso_decryption_key = $user_info[$decryption_key_claim] ?? null;

if (empty($sso_decryption_key)) {
    logSSOAuth($mysqli, 'UserInfo', 'Failed', $user_email, null, "Missing decryption key claim: $decryption_key_claim", $session_ip, $session_user_agent);
    http_response_code(400);
    exit("OpenID provider did not supply required encryption key claim ($decryption_key_claim)");
}

// Validate decryption key format (should be base64 encoded 16-byte key)
$normalized_key = normalizeBase64Key($sso_decryption_key);
if (!$normalized_key || strlen(base64_decode($normalized_key, true)) !== 16) {
    logSSOAuth($mysqli, 'UserInfo', 'Failed', $user_email, null, 'Invalid decryption key format or length', $session_ip, $session_user_agent);
    http_response_code(400);
    exit("Invalid encryption key format from OpenID provider");
}

// Fetch master key once for existing or new user handling
$site_master_key = null;
try {
    $settings_query = mysqli_query($mysqli, "
        SELECT config_site_encryption_master_key
        FROM settings
        WHERE company_id = 1
    ");
} catch (mysqli_sql_exception $e) {
    $settings_query = false;
}

if ($settings_query) {
    $settings_row = mysqli_fetch_assoc($settings_query);
    $site_master_key = $settings_row['config_site_encryption_master_key'] ?? null;
}

if (empty($site_master_key)) {
    logSSOAuth($mysqli, 'UserCreate', 'Failed', $user_email, null, 'SSO encryption master key not available', $session_ip, $session_user_agent);
    http_response_code(500);
    exit("OpenID SSO is not fully configured: encryption master key is missing. Please run the latest database migration.");
}

// Find or create user
$user_query = mysqli_query($mysqli, "
    SELECT user_id, user_name, user_password, user_auth_method, user_status, user_archived_at, user_type, user_token, user_specific_encryption_ciphertext, user_sso_decryption_key
    FROM users
    WHERE user_email = '$user_email' 
      AND user_type = 1
    LIMIT 1
");

$user_exists = mysqli_fetch_assoc($user_query);

if ($user_exists) {
    // Existing user - verify auth method and convert/update to SSO
    $user_id = $user_exists['user_id'];
    $user_name = $user_exists['user_name']; // Keep existing name
    
    if ($user_exists['user_status'] != 1 || !empty($user_exists['user_archived_at'])) {
        logSSOAuth($mysqli, 'UserVerification', 'Failed', $user_email, $user_id, 'User account inactive or archived', $session_ip, $session_user_agent);
        http_response_code(403);
        exit("Your account is inactive or archived. Please contact an administrator.");
    }

    $sso_ciphertext_result = generateSSODecryptionKey($site_master_key, $sso_decryption_key);
    if (!$sso_ciphertext_result) {
        logSSOAuth($mysqli, 'UserUpdate', 'Failed', $user_email, $user_id, 'Invalid SSO decryption key format during conversion', $session_ip, $session_user_agent);
        http_response_code(400);
        exit("Invalid encryption key format from OpenID provider");
    }

    $new_ciphertext = $sso_ciphertext_result['ciphertext'];

    mysqli_query($mysqli, "
        UPDATE users
        SET user_sso_decryption_key = '$sso_decryption_key',
            user_auth_method = 'openid',
            user_specific_encryption_ciphertext = '$new_ciphertext',
            user_updated_at = NOW()
        WHERE user_id = $user_id
    ");
    
    logSSOAuth($mysqli, 'UserUpdate', 'Success', $user_email, $user_id, 'Converted existing user to OpenID SSO', $session_ip, $session_user_agent);
} else {
    // New user - create account with SSO decryption key
    $placeholder_password = password_hash(randomString(), PASSWORD_DEFAULT);
    
    $sso_ciphertext_result = generateSSODecryptionKey($site_master_key, $sso_decryption_key);
    if (!$sso_ciphertext_result) {
        logSSOAuth($mysqli, 'UserCreate', 'Failed', $user_email, null, 'Invalid SSO decryption key format', $session_ip, $session_user_agent);
        http_response_code(400);
        exit("Invalid encryption key format from OpenID provider");
    }

    $user_specific_encryption_ciphertext = $sso_ciphertext_result['ciphertext'];
    
    $insert_query = mysqli_query($mysqli, "
        INSERT INTO users (
            user_name, 
            user_email, 
            user_password, 
            user_auth_method, 
            user_type, 
            user_status,
            user_specific_encryption_ciphertext,
            user_sso_decryption_key
        ) VALUES (
            '$user_name',
            '$user_email',
            '$placeholder_password',
            'openid',
            1,
            1,
            '$user_specific_encryption_ciphertext',
            '$sso_decryption_key'
        )
    ");
    
    if (!$insert_query) {
        logSSOAuth($mysqli, 'UserCreate', 'Failed', $user_email, null, 'Database insertion error: ' . mysqli_error($mysqli), $session_ip, $session_user_agent);
        http_response_code(500);
        exit("Failed to create user account");
    }
    
    $user_id = mysqli_insert_id($mysqli);
    logSSOAuth($mysqli, 'UserCreate', 'Success', $user_email, $user_id, 'New technician account created via OpenID', $session_ip, $session_user_agent);
}

// Setup session with encryption
$_SESSION['user_id'] = $user_id;
$_SESSION['csrf_token'] = randomString(32);
$_SESSION['logged'] = true;
$_SESSION['user_type'] = 1; // Agent
$_SESSION['login_method'] = 'openid';

// Get user's encryption ciphertext
$user_enc_query = mysqli_query($mysqli, "
    SELECT user_specific_encryption_ciphertext, user_sso_decryption_key
    FROM users
    WHERE user_id = $user_id
");

$user_enc_data = mysqli_fetch_assoc($user_enc_query);

if ($user_enc_data && !empty($user_enc_data['user_sso_decryption_key'])) {
    // Decrypt master key using SSO decryption key
    $site_encryption_master_key = decryptUserSpecificKeyWithSSO(
        $user_enc_data['user_specific_encryption_ciphertext'],
        $user_enc_data['user_sso_decryption_key']
    );
    
    if ($site_encryption_master_key) {
        // Setup encryption session key
        generateUserSessionKey($site_encryption_master_key);
        logSSOAuth($mysqli, 'SessionSetup', 'Success', $user_email, $user_id, 'Encryption session initialized', $session_ip, $session_user_agent);
    } else {
        $key = $user_enc_data['user_sso_decryption_key'];
        error_log("OpenID SSO session setup failed: invalid decryption key or ciphertext. key=" . substr($key, 0, 64) . " length=" . strlen($key));
        error_log("User ciphertext length=" . strlen($user_enc_data['user_specific_encryption_ciphertext']));
        logSSOAuth($mysqli, 'SessionSetup', 'Failed', $user_email, $user_id, 'Failed to decrypt encryption key', $session_ip, $session_user_agent);
        http_response_code(500);
        exit("Failed to setup encryption session");
    }
}

// Log successful login
$session_user_id = $user_id;
logAction("Login", "Success", "$user_name successfully logged in via OpenID", 0, $user_id);
logSSOAuth($mysqli, 'Login', 'Success', $user_email, $user_id, 'Technician successfully authenticated', $session_ip, $session_user_agent);

// Determine start page
$start_page = $config_start_page ?? "index.php";

// Clear OpenID session vars
unset($_SESSION['openid_state']);
unset($_SESSION['openid_nonce']);

// Redirect to dashboard
header("Location: /agent/$start_page");
exit();
