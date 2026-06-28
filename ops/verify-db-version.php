#!/usr/bin/env php
<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "CLI only.\n");
    exit(1);
}

$releaseDir = $argv[1] ?? dirname(__DIR__);
$releaseDir = realpath($releaseDir);

if ($releaseDir === false) {
    fwrite(STDERR, "Invalid release directory.\n");
    exit(1);
}

require $releaseDir . '/config.php';
require $releaseDir . '/includes/database_version.php';

$result = mysqli_query(
    $mysqli,
    'SELECT config_current_database_version FROM settings LIMIT 1'
);

if ($result === false) {
    fwrite(STDERR, 'Unable to query database version: ' . mysqli_error($mysqli) . PHP_EOL);
    exit(1);
}

$row = mysqli_fetch_assoc($result);
$current = (string) ($row['config_current_database_version'] ?? '');
$latest = (string) LATEST_DATABASE_VERSION;

if ($current === '' || $current !== $latest) {
    fwrite(
        STDERR,
        "Database version mismatch. Current: {$current}; expected: {$latest}\n"
    );
    exit(1);
}

echo "Database version is current: {$current}\n";
