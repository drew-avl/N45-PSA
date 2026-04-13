<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['edit_identity_provider'])) {

    validateCSRFToken($_POST['csrf_token']);

    $azure_client_id = sanitizeInput($_POST['azure_client_id']);
    $azure_client_secret = sanitizeInput($_POST['azure_client_secret']);

    // OpenID Connect Configuration
    $openid_enabled = isset($_POST['openid_enabled']) ? 1 : 0;
    $openid_client_id = sanitizeInput($_POST['openid_client_id']);
    $openid_client_secret = sanitizeInput($_POST['openid_client_secret']);
    $openid_discovery_url = sanitizeInput($_POST['openid_discovery_url']);
    $openid_decryption_key_claim = sanitizeInput($_POST['openid_decryption_key_claim']);
    $openid_scopes = sanitizeInput($_POST['openid_scopes']);
    $openid_response_type = sanitizeInput($_POST['openid_response_type']);

    // Validate OpenID configuration if enabled
    if ($openid_enabled) {
        if (empty($openid_discovery_url) || empty($openid_client_id) || empty($openid_client_secret)) {
            flash_alert("OpenID Connect is enabled but missing required configuration (Discovery URL, Client ID, or Client Secret)", "danger");
            redirect();
            exit;
        }

        // Validate URL format
        if (!filter_var($openid_discovery_url, FILTER_VALIDATE_URL)) {
            flash_alert("Invalid OpenID Discovery URL format", "danger");
            redirect();
            exit;
        }
    }

    mysqli_query($mysqli, "UPDATE settings SET 
        config_azure_client_id = '$azure_client_id', 
        config_azure_client_secret = '$azure_client_secret',
        config_openid_enabled = $openid_enabled,
        config_openid_client_id = '$openid_client_id',
        config_openid_client_secret = '$openid_client_secret',
        config_openid_discovery_url = '$openid_discovery_url',
        config_openid_decryption_key_claim = '$openid_decryption_key_claim',
        config_openid_scopes = '$openid_scopes',
        config_openid_response_type = '$openid_response_type'
        WHERE company_id = 1
    ");

    logAction("Settings", "Edit", "$session_name edited identity provider settings (Azure & OpenID)");

    flash_alert("Identity Provider Settings updated successfully");

    redirect();

}
