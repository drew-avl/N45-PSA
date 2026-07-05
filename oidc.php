<?php
/**
 * Compatibility shim.
 * The working implementation lives under /agent/openid_login.php and /agent/openid_callback.php.
 */
$action = $_GET['action'] ?? 'start';

if ($action === 'callback') {
    $query = $_SERVER['QUERY_STRING'] ?? '';
    // Remove action=callback from the query before forwarding.
    parse_str($query, $params);
    unset($params['action']);
    $new_query = http_build_query($params);
    header('Location: /agent/openid_callback.php' . ($new_query ? '?' . $new_query : ''));
    exit();
}

header('Location: /agent/openid_login.php');
exit();
