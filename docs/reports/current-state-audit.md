# Current-state UI & Repository Audit

## Summary
- Monolithic PHP application forked from ITFlow. Server-rendered pages using PHP templates in `includes/`.
- Frontend relies on legacy libraries in `plugins/` (AdminLTE, Bootstrap, jQuery, DataTables, Select2, FullCalendar, TinyMCE, Toastr, etc.).
- Database schema is in `db.sql` (~132 tables). Application configuration is primarily DB-driven via `settings` table.
- No existing native integrations for Level.io, CIPP, or SentinelOne detected.

## Entry points and auth
- `index.php` routes to `/agent/` or `/client/` depending on session. See `includes/session_init.php` and `includes/load_global_settings.php`.
- Session-based auth with optional OpenID Connect fields present in `settings` (Microsoft/CIPP-ready fields exist but no CIPP integration code found).

## Key directories
- `agent/` — primary technician-facing modules (tickets, assets, clients, invoices, projects, calendar, search).
- `admin/` — administrative screens (users, roles, settings, integrations, templates).
- `client/` — client portal views.
- `api/v1/` — REST-style endpoints for core resources.
- `includes/` — shared templates, auth checks, DB connection, header/footer.
- `plugins/` — third-party frontend libs.
- `ops/` — deployment and maintenance scripts.

## Important files
- `functions.php` — utility functions and crypto helpers.
- `includes/load_global_settings.php` — loads `settings` table into runtime config.
- `db.sql` — full schema (used for mapping database-backed features).
- `docs/DEPLOYMENT.md` and `ops/deploy.sh` — deployment instructions and scripts.

## Database schema (high level)
- Total CREATE TABLE entries scanned: 132.
- Key feature tables:
  - Tickets: `tickets`, `ticket_replies`, `ticket_attachments`, `ticket_history`, `ticket_statuses`, `ticket_watchers`, `ticket_assets`, `ticket_templates`, `ticket_views`
  - Assets: `assets`, `asset_*` (history, files, credentials, custom, tags, interfaces)
  - Clients: `clients`, `contacts`, `locations`, `client_*` (notes, tags, payment methods)
  - Users & roles: `users`, `user_roles`, `user_role_permissions`, `user_client_permissions`, `user_settings`
  - Billing: `invoices`, `invoice_items`, `payments`, `recurring_invoices`, `quotes`, `quote_items`
  - Projects & tasks: `projects`, `tasks`, `project_templates`, `task_templates`
  - Docs & credentials: `documents`, `document_files`, `credentials`, `credential_tags`
  - Integrations & keys: `api_keys`, `ai_models`, `ai_providers`
  - Settings & modules: `settings`, `modules`, `logs`, `app_logs`, `notifications`

## Integration scan
- Searched repository for references to Level/CIPP/Sentinel; no existing integration implementations found.
- `settings` table contains OpenID and Azure OAuth fields (CIPP-related fields present), and `api_keys` table exists for external credentials storage.

## Frontend tech debt and UX observations (current-state)
- UI is server-rendered with heavy use of jQuery and AdminLTE — typical legacy admin feel.
- Numerous distinct PHP pages (many full-page navigations) produce context switching and slow workflows for technicians.
- No centralized design tokens or component library; styles and interactions depend on plugins scattered in `plugins/`.
- Accessibility: no evidence of systematic a11y support; likely many WCAG 2.2 AA issues.
- Keyboard workflows appear minimal; global command palette/search is absent (there is `global_search.php`, but not a command-palette experience).

## Initial route & feature inventory (top-level)
- `agent/tickets.php` — Ticket queue view (maps to `tickets` and ticket-related tables).
- `agent/ticket.php` — Ticket detail (ticket header, replies, attachments).
- `agent/ticket_list.php`, `agent/ticket_kanban.php` — alternate ticket UIs.
- `agent/assets.php`, `agent/asset_details.php` — Asset list/detail (maps to `assets` and `asset_*`).
- `agent/clients.php`, `agent/client_overview.php` — Client workspace (clients, contacts, locations, contracts).
- `agent/invoices.php`, `agent/invoice.php` — Billing workflows (invoices, payments).
- `agent/projects.php`, `agent/project_details.php` — Projects and tasks (projects, tasks).
- `agent/calendar.php` — Scheduling view (calendar_events, calendars).
- `admin/users.php`, `admin/roles.php` — User and role management (users, user_roles, permissions).
- `api/v1/*` — REST endpoints for assets, clients, tickets, invoices, etc.
- `client/` — Client portal pages.

## Risks & constraints
- Monolithic PHP codebase means incremental frontend rewrites must interoperate with server-rendered routes.
- Deployment and migrations are DB-driven; careful migration and feature-flagging required.
- No existing Level.io/CIPP/SentinelOne connectors — these must be designed and added as first-class integrations.

## Next recommended steps (phase 1 continuation)
1. Produce a complete route and feature inventory (every PHP endpoint + mapping to tables).  
2. Extract role & permission mappings from `user_roles`, `user_role_permissions`, and `modules` tables.  
3. Audit every ticketing, client, and asset page for destructive actions and missing confirmations.  
4. Propose a migration-compatible UI architecture and integration framework design.

---

Generated by initial automated repository inspection. For the next pass I will produce a CSV-style route→feature→table mapping and a detailed `user-role` matrix. Please confirm to proceed with the full inventory extraction now.