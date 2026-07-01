# Data and API Compatibility Assessment

## Compatibility Position
The existing PHP routes, MariaDB schema, and API endpoints remain the compatibility contract. UI modernization should be incremental and preserve current records, identifiers, permissions, upload paths, and deployment behavior.

## Existing Data Sources
| Area | Tables / Routes | Compatibility Notes |
| --- | --- | --- |
| Tickets | `tickets`, `ticket_replies`, `ticket_history`, `ticket_assets`, `ticket_watchers`, `ticket_statuses` | Keep ticket IDs, prefixes, reply visibility, task relationships, and notification behavior. |
| Clients | `clients`, `contacts`, `locations`, `client_tags`, `user_client_permissions` | Client workspace must respect client-level access restrictions. |
| Assets | `assets`, `asset_interfaces`, `asset_tags`, `asset_files`, `asset_history` | Asset matching for integrations must avoid uncontrolled duplicates. |
| Billing | `quotes`, `quote_items`, `invoices`, `invoice_items`, `payments`, `recurring_invoices` | Financial workflows need explicit consequence review before write actions. |
| Documents | `documents`, `document_files`, `files`, `folders` | Existing files and document links must remain addressable. |
| Credentials | `credentials`, credential relation tables | Never silently discard encrypted data; masked display remains default. |
| Permissions | `users`, `user_roles`, `user_role_permissions`, `modules` | UI may hide controls, but backend permissions remain authoritative. |
| APIs | `api/v1/**` | Do not break current REST-style endpoints without a versioned migration. |

## POST and CSRF Compatibility
State changes should move from GET links with CSRF tokens in URLs to POST forms with body tokens. During migration, handlers may temporarily accept both `$_POST` and `$_GET` for previously linked actions. Once all callers are converted, remove GET state-change paths.

Downloads and exports may remain GET only when they are read-only and do not require a CSRF token. If a download action requires authorization beyond the session, prefer a short-lived server-side export token rather than the session CSRF token in the URL.

## Native Integration Data Model
Level.io, CIPP, and SentinelOne should share an integration framework instead of isolated tables. Add N45 migrations under `database/n45_migrations/` when schema work begins.

Minimum model concepts:

- `integrations`: provider, status, credential reference, health, API version.
- `integration_tenants`: provider tenant/account/site mapping.
- `integration_client_mappings`: PSA client/location to external tenant/site/group.
- `integration_asset_mappings`: PSA asset to external device/endpoint.
- `integration_events`: normalized event stream with idempotency key and source payload reference.
- `integration_jobs`: sync, retry, reconciliation, and dead-letter state.
- `integration_actions`: initiated technician actions and external results.
- `integration_audit`: immutable material-action audit events.

Every synchronized record needs source platform, source tenant, source record ID, last attempted sync, last successful sync, sync state, error state, and ownership rules.

## Search Compatibility
Universal search should initially aggregate existing SQL queries and API endpoints, then add a normalized search index when needed. Search must respect:

- User role permissions.
- Client access restrictions.
- Credential masking.
- Integration-specific security permissions.
- Tenant and cross-client isolation.

## API Evolution Rules
- Additive fields are preferred.
- New integration endpoints should live under a versioned namespace.
- External API calls must be wrapped behind provider adapters.
- Use mocked external APIs in tests.
- Do not require production integration credentials in normal CI.
- Preserve existing customer Microsoft Entra login while technician OIDC defaults to Authentik.

## Migration Rules
- N45 migrations go in `database/n45_migrations/`.
- Filenames use `YYYYMMDD_NNN_description.sql`.
- Migrations must be safe against existing installations.
- Idempotent checks are preferred where MariaDB supports them.
- Secret rotation must not delete mappings or historical audit records.

