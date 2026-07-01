# Component Inventory and Patterns

## Existing UI Building Blocks
The current app is PHP-rendered with shared includes and AdminLTE/jQuery plugins:

| Current Pattern | Location | Observed Role |
| --- | --- | --- |
| App header and assets | `includes/header.php` | Loads AdminLTE, plugins, and custom N45 CSS. |
| Footer and scripts | `includes/footer.php` | Loads shared JS and confirmation modal. |
| Technician top nav | `includes/top_nav.php` | Search, quick links, user controls. |
| Technician side nav | `agent/includes/side_nav.php` | Module navigation and counts. |
| Client side nav | `agent/includes/client_side_nav.php` | Client-scoped navigation. |
| Filter wrappers | `includes/filter_header.php`, `includes/filter_footer.php` | Repeated table filter layout. |
| Confirmation modal | `includes/inc_confirm_modal.php`, `js/confirm_modal.js` | Shared destructive-action confirmation. |
| Ajax modals | `js/ajax_modal.js`, `agent/modals/**`, `admin/modals/**` | Create/edit/detail modal workflow. |
| Tables | Per-route PHP templates | Server-rendered tables with mixed controls. |

## Target Component Set
Implement these as small PHP includes/helpers first, then progressively replace route-local copies:

| Component | Responsibility | Initial Integration |
| --- | --- | --- |
| App shell | Stable header/sidebar/content landmarks | Extend existing includes. |
| Command search | Universal search and actions | Wrap `agent/global_search.php` and add command endpoint later. |
| Record header | Entity identity, status, ownership, primary actions | Ticket, client, asset, invoice detail pages. |
| Data grid controls | Saved view, filters, density, columns, bulk actions | Tickets, clients, assets first. |
| POST action control | State-changing action rendered as form/button | Replace `post.php?...csrf_token` anchors. |
| Status badge | Text/icon/color status with accessible label | Ticket, asset, invoice, integration status. |
| Timeline event | Native and integration activity rows | Ticket replies/history first. |
| Context panel | Related records and integration panels | Ticket and asset detail. |
| Empty/error/permission state | Consistent no data, denied, partial failure UI | Shared include usable from every module. |
| Modal/drawer shell | Accessible label, trap, close/restore focus | Replace existing ajax modal wrapper. |

## POST Action Pattern
State-changing actions must be forms:

```php
<form method="post" action="post.php" class="m-0 d-inline">
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
    <input type="hidden" name="archive_ticket" value="<?= $ticket_id ?>">
    <button type="submit" class="dropdown-item text-danger confirm-link">
        <i class="fas fa-fw fa-archive mr-2"></i>Archive
    </button>
</form>
```

The post handler should read `$_POST` for state changes. Temporary GET fallback may be kept only while all callers are being migrated, but new UI must not emit CSRF tokens in URLs.

## Modal Pattern
Every modal needs:

- `role="dialog"` and `aria-modal="true"`.
- A stable title connected with `aria-labelledby`.
- Focus moved into the modal on open.
- Focus restored to the trigger on close.
- Escape and close button behavior.
- Non-JS route fallback for critical create/edit flows.

## Table Pattern
Table pages should expose:

- One visible search field.
- Human-readable filters.
- Saved views.
- Bulk action bar only when rows are selected.
- POST-backed bulk actions.
- Persistent density and column visibility preferences.
- Pagination or virtual scrolling for large datasets.

## Integration Panel Pattern
Level.io, CIPP, and SentinelOne panels should show:

- Current health/coverage state.
- Last successful sync and stale-data warning.
- Exceptions requiring attention.
- Mapped source identifiers.
- Permission-controlled actions.
- Source record link when available.
- Expandable diagnostics for authorized users only.

