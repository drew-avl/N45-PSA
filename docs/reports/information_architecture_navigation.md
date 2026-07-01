# Information Architecture and Navigation Model

## Purpose
N45-PSA should move from a route-heavy legacy admin model toward a stable operational workspace. The backend remains the source of truth; this model reorganizes access, wayfinding, and context without removing existing features.

## Primary Navigation
The technician-facing sidebar should use a small number of durable groups:

| Group | Primary Destinations | Notes |
| --- | --- | --- |
| Home | Role dashboard, recent work, notifications | Landing page adapts to role and saved preference. |
| Service | Tickets, ticket kanban, dispatch, recurring tickets, time | Ticket queue remains the primary technician workflow. |
| Clients | Clients, contacts, locations, shared items | Client workspace is the hub for related records. |
| Assets | Assets, networks, racks, software, domains, certificates | Asset detail becomes the unified technical record. |
| Projects | Projects, tasks, templates | Shares task and activity patterns with tickets. |
| Sales | Quotes, products, revenues | Commercial workflow before invoice. |
| Billing | Invoices, payments, expenses, recurring invoices | Financial actions must show consequence and state. |
| Documentation | Documents, files, credentials | Credential access stays permission-gated and auditable. |
| Reports | Operational, financial, security, utilization reports | Reports should drill into filtered source records. |
| Automation | Notifications, scheduled jobs, integration routing | First-class home for integration event rules. |
| Administration | Users, roles, modules, settings, providers, API keys | Hidden from users without admin permission. |

## Global Top Bar
The top bar should provide persistent controls that reduce navigation:

- Universal search and command palette, opened with Ctrl/Cmd+K.
- Quick create for ticket, client, contact, asset, quote, invoice, task, and note.
- Active timer with start, pause, and submit states.
- Notifications with action filters.
- Recently viewed records.
- User and organization menu.
- Help, shortcuts, and safe sign-out.

## Workspace Pattern
Operational pages should share the same structure:

1. Breadcrumb or scoped location.
2. Compact record/page header with status and primary actions.
3. View controls: saved views, density, columns, sort, filters.
4. Main work surface: table, split view, detail, or timeline.
5. Optional context panel for related records and integration status.

## Core Workspaces
Tickets:
Ticket queue defaults to saved views and split detail. Ticket detail uses a persistent header, conversation timeline, task panel, and context panel for client, asset, agreement, invoice, and integration data.

Clients:
Client overview is the operational hub for contacts, locations, tickets, assets, agreements, projects, billing, documents, credentials, and native integrations. The overview should surface risks first: open SLA issues, overdue invoices, expiring domains/certificates, unsupported assets, stale integrations, and missing documentation.

Assets:
Asset detail merges PSA-owned data with Level.io, SentinelOne, and relevant CIPP/Entra context. Source labels and sync state must be visible when external data is shown.

Search:
Search returns grouped, permission-filtered results across tickets, clients, contacts, locations, assets, documents, quotes, invoices, vendors, and integration records. Results should include owner client, status, last activity, and safe matching context.

## Client Portal Separation
Client authentication and navigation remain separate from technician authentication. Client portal pages should never expose technician login controls or technician-only actions. Technician local login remains an explicit fallback route only.

## Integration Navigation
Level.io, CIPP, and SentinelOne should appear in three places:

- Administration: connection health, credentials, mappings, diagnostics, routing rules.
- Client workspace: tenant/account/site summary and actionable exceptions.
- Asset/ticket context panels: mapped device, alert, incident, standard, or action history.

## Mobile Model
Mobile should prioritize technician field workflows:

- Assigned tickets and schedule.
- Ticket reply/internal note/time entry.
- Contact/site details.
- Photos and attachments.
- Status and timer changes.

Large administrative tables should not collapse into unusable card stacks; mobile pages should expose focused list views with primary metadata and actions.

