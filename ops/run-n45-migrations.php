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

$migrationDir = $releaseDir . '/database/n45_migrations';

function n45RandomString(int $length = 32): string
{
    $bytes = random_bytes((int) ceil($length * 3 / 4));

    return substr(
        rtrim(strtr(base64_encode($bytes), '+/', '-_'), '='),
        0,
        $length
    );
}

function n45ColumnExists(mysqli $mysqli, string $table, string $column): bool
{
    $statement = mysqli_prepare(
        $mysqli,
        'SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?'
    );

    if ($statement === false) {
        throw new RuntimeException('Unable to inspect schema: ' . mysqli_error($mysqli));
    }

    mysqli_stmt_bind_param($statement, 'ss', $table, $column);
    mysqli_stmt_execute($statement);
    mysqli_stmt_bind_result($statement, $count);
    mysqli_stmt_fetch($statement);
    mysqli_stmt_close($statement);

    return (int) $count > 0;
}

function ensureSsoMasterKey(mysqli $mysqli): void
{
    if (!n45ColumnExists($mysqli, 'settings', 'config_site_encryption_master_key')) {
        return;
    }

    $result = mysqli_query(
        $mysqli,
        "SELECT company_id
         FROM settings
         WHERE config_site_encryption_master_key IS NULL
            OR config_site_encryption_master_key = ''"
    );

    if ($result === false) {
        throw new RuntimeException('Unable to inspect SSO master key: ' . mysqli_error($mysqli));
    }

    $companyIds = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $companyIds[] = (int) $row['company_id'];
    }
    mysqli_free_result($result);

    foreach ($companyIds as $companyId) {
        $key = n45RandomString(32);
        $statement = mysqli_prepare(
            $mysqli,
            'UPDATE settings SET config_site_encryption_master_key = ? WHERE company_id = ?'
        );

        if ($statement === false) {
            throw new RuntimeException('Unable to prepare SSO master key update: ' . mysqli_error($mysqli));
        }

        mysqli_stmt_bind_param($statement, 'si', $key, $companyId);

        if (!mysqli_stmt_execute($statement)) {
            $error = mysqli_stmt_error($statement);
            mysqli_stmt_close($statement);
            throw new RuntimeException('Unable to populate SSO master key: ' . $error);
        }

        mysqli_stmt_close($statement);
        echo "Populated SSO site encryption master key for company_id {$companyId}.\n";
    }
}

if (!is_dir($migrationDir)) {
    echo "No N45 migration directory found; nothing to apply.\n";
    exit(0);
}

$createTableSql = <<<'SQL'
CREATE TABLE IF NOT EXISTS n45_schema_migrations (
    migration VARCHAR(255) NOT NULL PRIMARY KEY,
    checksum CHAR(64) NOT NULL,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
SQL;

if (!mysqli_query($mysqli, $createTableSql)) {
    fwrite(STDERR, 'Unable to create migration table: ' . mysqli_error($mysqli) . PHP_EOL);
    exit(1);
}

$files = glob($migrationDir . '/*.sql') ?: [];
sort($files, SORT_STRING);

foreach ($files as $file) {
    $name = basename($file);

    if (!preg_match('/^\d{8}_\d{3}_[a-z0-9_]+\.sql$/', $name)) {
        fwrite(STDERR, "Invalid migration filename: {$name}\n");
        exit(1);
    }

    $sql = file_get_contents($file);
    if ($sql === false) {
        fwrite(STDERR, "Unable to read migration: {$name}\n");
        exit(1);
    }

    $checksum = hash('sha256', $sql);

    $statement = mysqli_prepare(
        $mysqli,
        'SELECT checksum FROM n45_schema_migrations WHERE migration = ?'
    );
    if ($statement === false) {
        fwrite(STDERR, 'Unable to inspect migration table: ' . mysqli_error($mysqli) . PHP_EOL);
        exit(1);
    }
    mysqli_stmt_bind_param($statement, 's', $name);
    mysqli_stmt_execute($statement);
    $result = mysqli_stmt_get_result($statement);
    $existing = mysqli_fetch_assoc($result);
    mysqli_stmt_close($statement);

    if ($existing !== null) {
        if (!hash_equals((string) $existing['checksum'], $checksum)) {
            fwrite(
                STDERR,
                "Applied migration was modified: {$name}. Add a new migration instead.\n"
            );
            exit(1);
        }

        echo "Already applied: {$name}\n";
        continue;
    }

    echo "Applying: {$name}\n";

    if (!mysqli_begin_transaction($mysqli)) {
        fwrite(STDERR, 'Unable to start transaction: ' . mysqli_error($mysqli) . PHP_EOL);
        exit(1);
    }

    try {
        if (!mysqli_multi_query($mysqli, $sql)) {
            throw new RuntimeException(mysqli_error($mysqli));
        }

        do {
            if ($result = mysqli_store_result($mysqli)) {
                mysqli_free_result($result);
            }

            if (!mysqli_more_results($mysqli)) {
                break;
            }
        } while (mysqli_next_result($mysqli));

        if (mysqli_errno($mysqli) !== 0) {
            throw new RuntimeException(mysqli_error($mysqli));
        }

        $insert = mysqli_prepare(
            $mysqli,
            'INSERT INTO n45_schema_migrations (migration, checksum) VALUES (?, ?)'
        );
        if ($insert === false) {
            throw new RuntimeException(mysqli_error($mysqli));
        }
        mysqli_stmt_bind_param($insert, 'ss', $name, $checksum);

        if (!mysqli_stmt_execute($insert)) {
            throw new RuntimeException(mysqli_stmt_error($insert));
        }

        mysqli_stmt_close($insert);

        if (!mysqli_commit($mysqli)) {
            throw new RuntimeException(mysqli_error($mysqli));
        }
    } catch (Throwable $exception) {
        mysqli_rollback($mysqli);
        fwrite(
            STDERR,
            "Migration failed: {$name}: {$exception->getMessage()}\n"
        );
        exit(1);
    }
}

try {
    ensureSsoMasterKey($mysqli);
} catch (Throwable $exception) {
    fwrite(STDERR, 'SSO master key repair failed: ' . $exception->getMessage() . PHP_EOL);
    exit(1);
}

echo "N45 migrations are current.\n";
