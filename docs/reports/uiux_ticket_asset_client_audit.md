# UI/UX Audit — Tickets, Clients, Assets

Scope
- Files reviewed: [agent/ticket.php](agent/ticket.php), [agent/tickets.php](agent/tickets.php), [agent/assets.php](agent/assets.php), [agent/asset_details.php](agent/asset_details.php), [agent/clients.php](agent/clients.php), [agent/client_overview.php](agent/client_overview.php).

Summary
- Core flows (ticket view/list, asset view/list, client list/overview) work functionally, but surface several UX, accessibility, and safety issues that increase cognitive load, risk data loss, and may block keyboard/screen-reader users.

Key Findings
- Destructive actions performed via GET links with CSRF token in URL (e.g. close/resolve/reopen tickets, archive/delete clients). See: [agent/ticket.php](agent/ticket.php), [agent/tickets.php](agent/tickets.php), [agent/clients.php](agent/clients.php).
  - Risk: GET state changes are fragile (bookmarks, crawlers) and placing CSRF tokens in URLs exposes them in logs and referrers.

- Confirmation UI depends on client-side JS (class `confirm-link`) and may not provide a server-side fallback. If JS disabled, destructive actions could execute without confirmation.

- Modal dialogs (`ajax-modal`) are used heavily for create/edit flows (tickets, assets, clients). There is likely no focus trapping, `role="dialog"` ARIA attributes, or clear keyboard handling.
  - Risk: screen-reader/keyboard users can lose context; keyboard users may not be able to interact reliably.

- Autosave on blur for important fields (e.g. `textarea` with `onblur="updateAssetNotes(...)"` in [agent/asset_details.php](agent/asset_details.php)).
  - Risk: accidental focus loss causes writes without explicit user intent; no visible saving state.

- Bulk actions, export/import, and other advanced controls are hidden or rely on JS; when JS is missing these features may be inaccessible (no progressive enhancement).
  - Files: [agent/tickets.php](agent/tickets.php), [agent/assets.php](agent/assets.php), [agent/clients.php](agent/clients.php).

- Icon-only buttons and color-only status indicators (badges) are common; many buttons lack explicit `aria-label` or accessible text. Contrast and semantics weren't audited but are likely inconsistent.

- Multiple small SQL queries per page (counts, related-entity queries) cause content shifts while the page loads; this affects perceived performance and layout stability on slow connections.

Recommendations (priority)
1. Replace all state-changing GET links with server-side POST endpoints (forms) that require CSRF tokens sent in request body or header — never in URL.
2. Ensure every destructive action has a server-side confirmation (POST-only), not just a JS prompt. Keep `confirm-link` but make it a progressive enhancement only.
3. Improve modal accessibility: add `role="dialog"`, `aria-modal="true"`, a visible headline, keyboard-focus trap on open, and restore focus on close. Provide a non-JS fallback to full-page forms for critical flows.
4. Replace `onblur` autosave with explicit Save/Update controls or reliable debounced auto-save with a visible saving indicator and undo where possible.
5. Make bulk actions progressively enhanced: provide an accessible fallback UI for non-JS environments (e.g., batch form with server-handled actions) and ensure proper confirmation for destructive bulk ops.
6. Add accessible labels (`aria-label` or visible labels) to icon-only action buttons and ensure status badges include text/content not only color. Add `sr-only` (visually-hidden) text where appropriate.
7. Run automated accessibility tests (axe, Lighthouse) and fix high-priority issues: headings hierarchy, form labels, color contrast, focus order.
8. Reduce N+1 SQL patterns on pages with many small counts: consolidate counts in a single aggregated query to improve perceived performance and avoid layout shifts.

Next Steps
- Apply quick wins: convert critical ticket/close/resolve links to POST endpoints, add server-side confirmations, and stop exposing CSRF tokens in URLs.
- Implement an accessible modal wrapper component (aria roles, focus trap, keyboard close) and replace `ajax-modal` usage incrementally.
- Run `axe-core` or Lighthouse across the targeted pages and produce a prioritized remediation list.

If you want, I can:
- Open a PR that implements (A) POST-based ticket close/resolve endpoints and (B) an accessible modal wrapper and convert one modal as an example.
- Run an automated accessibility scan and attach the report.

