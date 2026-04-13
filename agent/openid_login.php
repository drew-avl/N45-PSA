<?php
/**
 * OpenID Connect Authorization Initiator for Agent Portal
 * Redirects user to OpenID provider for authentication
 */

if (!file_exists('../config.php')) {
    header("Location: /setup");
    exit();
}

require_once "../config.php";
require_once "../functions.php";

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

// Get OpenID configuration
$openid_config = getOpenIDConfig($mysqli);

if (!$openid_config) {
    http_response_code(400);
    exit("OpenID Connect is not configured");
}

// Fetch provider metadata
$metadata = fetchOpenIDMetadata($openid_config['discovery_url']);

if (!$metadata) {
    http_response_code(400);
    exit("Failed to fetch OpenID Connect provider metadata");
}

// Generate authorization URL
// Callback URL must be absolute
$callback_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https://' : 'http://') 
    . $_SERVER['HTTP_HOST'] 
    . '/agent/openid_callback.php';

$auth_url = generateOpenIDAuthorizationURL(
    $metadata['authorization_endpoint'],
    $openid_config['client_id'],
    $callback_url,
    $openid_config['scopes'],
    $openid_config['response_type']
);

// Redirect to provider
header("Location: $auth_url");
exit();
