# Testing, Accessibility, and Deployment Plan

## Required Local Validation
Before proposing completion for UI/security work:

```bash
git diff --check
php -l <each changed php file>
bash -n <each changed shell script>
rg -n "<<<<<<<|=======|>>>>>>>" .
rg -n -F "post.php?" agent admin client --glob "*.php"
rg -n -F "&csrf_token=" agent admin client --glob "*.php"
```

The final two searches are used to identify remaining URL-token actions. Read-only downloads may be separately reviewed; state-changing actions must be POST forms.

## Automated Test Targets
Initial high-value tests:

- Authentication: technician OIDC default, local technician fallback, client login separation, Microsoft Entra client login.
- Permissions: hidden/disabled controls plus backend enforcement for tickets, credentials, integrations, and billing.
- Ticketing: create, reply, internal note, status change, assignment, schedule, task completion, watcher removal.
- Clients: create/edit, archive/restore, contact/location management.
- Assets: create/edit, archive/restore, relationship links, related tickets.
- Billing: quote totals, invoice totals, payments, recurring preview.
- Search: permission-filtered results and no credential leakage.
- Destructive actions: confirmation and POST-only submission.
- Integrations: mocked auth, webhook validation, mapping, duplicate alert suppression, retry, stale-state display, audit event creation.

## Accessibility Validation
Target WCAG 2.2 AA.

Automated checks:

- Lighthouse or axe scan on dashboard, ticket queue, ticket detail, client overview, asset detail, invoice detail, admin users, and client ticket page.
- Contrast review for N45 light and dark tokens.
- HTML validity spot checks on templates touched by the redesign.

Manual checks:

- Tab through top nav, sidebar, ticket queue, ticket detail, modal, and dropdown actions.
- Open and close modal with keyboard only.
- Confirm focus returns to the triggering control.
- Complete a ticket task and remove a watcher using keyboard only.
- Verify every icon-only action has a name through visible text, title, or ARIA label.
- Verify every status badge includes text and does not rely on color alone.
- Confirm reduced-motion settings do not block workflow comprehension.

## Deployment Readiness
Use `docs/DEPLOYMENT.md` for the production release process. Additional UI release gates:

- No uncommitted secrets, `config.php`, database dumps, credentials, or user data.
- N45 migrations, if any, are in `database/n45_migrations/` and are idempotent or guarded.
- No production server access during development validation.
- CI must pass before merging `develop` to `master`.
- Release tags are immutable and named `n45-vYYYY.MM.N`.

## Smoke Test Script Additions
When the app has a local test harness, add smoke checks for:

- `/login.php`
- `/agent/`
- `/agent/tickets.php`
- `/agent/global_search.php`
- `/agent/clients.php`
- `/agent/assets.php`
- `/client/`

Each smoke check should verify HTTP success, no raw PHP errors, and expected page landmarks.

## Known Current Gaps
- The repository does not yet contain a complete browser-based accessibility test harness.
- Many existing modules still use legacy AdminLTE/jQuery modal patterns.
- Several URL-token actions outside the core workflow pages still need conversion or classification as read-only downloads.

