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

echo "N45 migrations are current.\n";
