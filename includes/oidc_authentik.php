<?php
/*
 * Authentik OIDC helper functions for ITFlow.
 * No Composer dependency required. Supports OIDC Authorization Code + PKCE
 * and RS256 ID token validation against the provider JWKS.
 */

function oidcBase64UrlDecode($input)
{
    $input = strtr($input, '-_', '+/');
    $padding = strlen($input) % 4;
    if ($padding) {
        $input .= str_repeat('=', 4 - $padding);
    }
    return base64_decode($input, true);
}

function oidcBase64UrlEncode($input)
{
    return rtrim(strtr(base64_encode($input), '+/', '-_'), '=');
}

function oidcJsonDecode($json, $context = 'OIDC response')
{
    $decoded = json_decode($json, true);
    if (!is_array($decoded)) {
        throw new Exception("Invalid $context JSON");
    }
    return $decoded;
}

function oidcHttpJson($url, $method = 'GET', array $fields = [], array $headers = [])
{
    $ch = curl_init($url);
    $curlHeaders = array_merge(['Accept: application/json'], $headers);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => false,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_USERAGENT => 'ITFlow Authentik OIDC',
        CURLOPT_HTTPHEADER => $curlHeaders,
    ]);

    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($fields, '', '&', PHP_QUERY_RFC3986));
    }

    $body = curl_exec($ch);
    $error = curl_error($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($body === false || $status < 200 || $status > 299) {
        throw new Exception('OIDC HTTP request failed: ' . ($error ?: 'HTTP ' . $status));
    }

    return oidcJsonDecode($body);
}

function oidcDiscover($issuer)
{
    $issuer = rtrim(trim($issuer), '/');
    if (!filter_var($issuer, FILTER_VALIDATE_URL) || stripos($issuer, 'https://') !== 0) {
        throw new Exception('OIDC issuer must be an HTTPS URL');
    }

    $discovery = oidcHttpJson($issuer . '/.well-known/openid-configuration');
    foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'issuer'] as $required) {
        if (empty($discovery[$required])) {
            throw new Exception("OIDC discovery document missing $required");
        }
    }

    if (rtrim($discovery['issuer'], '/') !== $issuer) {
        throw new Exception('OIDC issuer mismatch in discovery document');
    }

    return $discovery;
}

function oidcAsn1Length($length)
{
    if ($length < 128) {
        return chr($length);
    }
    $temp = ltrim(pack('N', $length), "\x00");
    return chr(0x80 | strlen($temp)) . $temp;
}

function oidcAsn1Integer($value)
{
    if ($value === '' || $value === false) {
        throw new Exception('Invalid RSA integer');
    }
    if (ord($value[0]) > 0x7f) {
        $value = "\x00" . $value;
    }
    return "\x02" . oidcAsn1Length(strlen($value)) . $value;
}

function oidcAsn1Sequence($value)
{
    return "\x30" . oidcAsn1Length(strlen($value)) . $value;
}

function oidcAsn1BitString($value)
{
    return "\x03" . oidcAsn1Length(strlen($value) + 1) . "\x00" . $value;
}

function oidcJwkToPem(array $jwk)
{
    if (($jwk['kty'] ?? '') !== 'RSA' || empty($jwk['n']) || empty($jwk['e'])) {
        throw new Exception('Unsupported JWKS key type');
    }

    $modulus = oidcBase64UrlDecode($jwk['n']);
    $exponent = oidcBase64UrlDecode($jwk['e']);
    $rsaPublicKey = oidcAsn1Sequence(oidcAsn1Integer($modulus) . oidcAsn1Integer($exponent));

    // rsaEncryption OID: 1.2.840.113549.1.1.1 + NULL
    $algorithmIdentifier = oidcAsn1Sequence("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . "\x05\x00");
    $subjectPublicKeyInfo = oidcAsn1Sequence($algorithmIdentifier . oidcAsn1BitString($rsaPublicKey));

    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

function oidcVerifyIdToken($jwt, array $jwks, $issuer, $clientId, $nonce)
{
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
        throw new Exception('Invalid OIDC ID token format');
    }

    [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
    $header = oidcJsonDecode(oidcBase64UrlDecode($encodedHeader), 'ID token header');
    $claims = oidcJsonDecode(oidcBase64UrlDecode($encodedPayload), 'ID token claims');
    $signature = oidcBase64UrlDecode($encodedSignature);
    $signedData = $encodedHeader . '.' . $encodedPayload;

    if (($header['alg'] ?? '') !== 'RS256') {
        throw new Exception('Unsupported OIDC signing algorithm');
    }

    $kid = $header['kid'] ?? null;
    $matchingKey = null;
    foreach (($jwks['keys'] ?? []) as $key) {
        if ($kid === null || ($key['kid'] ?? null) === $kid) {
            $matchingKey = $key;
            break;
        }
    }

    if (!$matchingKey) {
        throw new Exception('No matching OIDC signing key found');
    }

    $pem = oidcJwkToPem($matchingKey);
    $verified = openssl_verify($signedData, $signature, $pem, OPENSSL_ALGO_SHA256);
    if ($verified !== 1) {
        throw new Exception('OIDC ID token signature verification failed');
    }

    $issuer = rtrim($issuer, '/');
    if (rtrim($claims['iss'] ?? '', '/') !== $issuer) {
        throw new Exception('OIDC ID token issuer mismatch');
    }

    $aud = $claims['aud'] ?? null;
    $audValid = is_array($aud) ? in_array($clientId, $aud, true) : hash_equals((string)$clientId, (string)$aud);
    if (!$audValid) {
        throw new Exception('OIDC ID token audience mismatch');
    }

    if (is_array($aud) && count($aud) > 1 && !empty($claims['azp']) && !hash_equals((string)$clientId, (string)$claims['azp'])) {
        throw new Exception('OIDC authorized party mismatch');
    }

    $now = time();
    if (empty($claims['exp']) || intval($claims['exp']) < $now - 60) {
        throw new Exception('OIDC ID token expired');
    }
    if (!empty($claims['nbf']) && intval($claims['nbf']) > $now + 60) {
        throw new Exception('OIDC ID token not yet valid');
    }
    if (!empty($claims['iat']) && intval($claims['iat']) > $now + 300) {
        throw new Exception('OIDC ID token issued in the future');
    }
    if (!empty($nonce) && !hash_equals((string)$nonce, (string)($claims['nonce'] ?? ''))) {
        throw new Exception('OIDC nonce mismatch');
    }

    return $claims;
}

function oidcClaim(array $claims, $claimName)
{
    $claimName = trim((string)$claimName);
    if ($claimName === '') {
        return null;
    }

    if (array_key_exists($claimName, $claims)) {
        return $claims[$claimName];
    }

    // Optional dotted path support, e.g. user.encryption_key
    $current = $claims;
    foreach (explode('.', $claimName) as $part) {
        if (!is_array($current) || !array_key_exists($part, $current)) {
            return null;
        }
        $current = $current[$part];
    }
    return $current;
}

function oidcCurrentRedirectUri()
{
    $proto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? null;
    if (!$proto) {
        $proto = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    }
    $host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?? ($_SERVER['HTTP_HOST'] ?? ($GLOBALS['config_base_url'] ?? ''));
    return $proto . '://' . $host . '/oidc.php?action=callback';
}
