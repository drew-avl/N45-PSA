# N45-PSA Engineering Instructions

## Project

N45-PSA is a customized ITFlow fork used by N45 Technology Solutions.

The production application runs on Linux, Apache, PHP, and MariaDB.

## Git workflow

* Never work directly on `master`.
* Start feature branches from `develop`.
* Feature branches merge into `develop`.
* `develop` merges into `master` only after CI passes.
* Production releases use immutable tags named `n45-vYYYY.MM.N`.
* Never move, recreate, or overwrite an existing release tag.

## Production safety

* Do not access or modify the production server.
* Do not modify `/var/www/n45-psa/current`.
* Do not execute database changes against production.
* Do not commit `config.php`, credentials, secrets, tokens, database dumps, or user data.
* Do not assume a migration exists; inspect the repository first.

## Database migrations

* N45 migrations belong in `database/n45_migrations/`.
* Use filenames formatted as `YYYYMMDD_NNN_description.sql`.
* Migrations must be safe to run against an existing installation.
* Prefer idempotent schema checks where MariaDB syntax permits.
* Never silently discard encrypted data.

## Authentication requirements

* Technician authentication defaults to OpenID Connect through Authentik.
* Local technician authentication remains available only as an explicit fallback.
* Client authentication must remain separate from technician authentication.
* Preserve the existing customer Microsoft Entra login.
* Do not expose technician login controls on the client login page.
* Do not expose client authentication controls on the local technician page.

## Required validation

Before proposing completion:

* Run `git diff --check`.
* Run `php -l` on every changed PHP file.
* Run `bash -n` on every changed shell script.
* Check for unresolved Git conflict markers.
* Report every changed file.
* Report every command executed and its result.
* Do not commit until the user approves the diff.
