# Incremental Implementation Plan and Milestones

## Milestone 0: Stabilize Current Work
Goal: finish the current security and documentation pass without expanding blast radius.

- Keep feature work off `master`.
- Finish POST conversion for remaining high-risk `post.php?...csrf_token` anchors in core workflows.
- Run required PHP, shell, diff, and conflict-marker checks.
- Record branch-base exception if local changes prevent checkout from `develop`.

Exit criteria:
- No new state-changing GET links in touched core pages.
- Changed PHP files pass `php -l`.
- `git diff --check` passes.

## Milestone 1: Foundation
Goal: make the existing PHP UI feel coherent without replacing the backend.

- Extend `css/itflow_custom.css` token coverage.
- Add app-shell landmarks and accessible focus states.
- Standardize POST action controls.
- Improve confirmation modal accessibility.
- Define table, form, status, record header, and empty-state includes.
- Add density mode preference storage.

Exit criteria:
- Tickets, clients, assets, and invoices use the same action/control patterns.
- Dark mode is token-driven and reviewed intentionally.
- Core modals have labels, focus behavior, and Escape support.

## Milestone 2: Core Workflows
Goal: improve daily technician and dispatcher workflows.

- Ticket queue saved views and clearer filters.
- Ticket detail record header and timeline cleanup.
- Client workspace overview with risk indicators.
- Asset detail context panels and relationship cleanup.
- Global search grouped by result type with keyboard navigation.
- Timer visibility and one-click ticket association.

Exit criteria:
- Technician can triage, reply, update status, assign, and log time without repeated page hunting.
- Dispatcher can inspect queue health and unassigned/SLA-risk tickets quickly.
- Client, ticket, and asset records preserve context when related records are opened.

## Milestone 3: Native Integrations
Goal: introduce Level.io, CIPP, and SentinelOne as first-class platform data.

- Add integration framework migrations.
- Add credential, connection-health, mapping, sync job, event, and audit models.
- Build admin mapping and diagnostics UI.
- Add read-only panels in client, asset, and ticket views.
- Add alert-to-ticket correlation with duplicate suppression.
- Add action framework with permission checks and confirmation.

Exit criteria:
- External records retain source identifiers and sync state.
- Integration outages do not block local PSA workflows.
- Search and dashboards can show permitted integration records.

## Milestone 4: Commercial and Supporting Workflows
Goal: carry the same interaction system through financial and documentation modules.

- Quote and invoice consequence review.
- Agreement/recurring billing preview states.
- Documentation templates, versioning, and relationship views.
- Credential reveal/copy audit improvements.
- Vendor and purchasing cleanup.

Exit criteria:
- Financial actions show totals and effects before saving.
- Credential and document workflows remain auditable and permission-safe.

## Milestone 5: Testing, Accessibility, and Release Readiness
Goal: prove the redesign is deployable.

- Add automated tests for authentication, permissions, ticket creation, ticket response, status change, client/asset edit, quote/invoice totals, destructive confirmations, and search.
- Add accessibility scans for core pages.
- Add manual keyboard test scripts.
- Update deployment docs with UI validation and rollback expectations.
- Capture before/after screenshots for core workflows.

Exit criteria:
- Required validation passes.
- High-priority accessibility issues are resolved or tracked.
- Release can be tagged immutably using `n45-vYYYY.MM.N` after CI passes.

