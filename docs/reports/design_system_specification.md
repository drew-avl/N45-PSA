# Design System Specification

## Direction
N45-PSA should feel calm, precise, dense, and operational. The current CSS foundation in `css/itflow_custom.css` already introduces an N45 token layer over AdminLTE. Future UI work should use those tokens instead of one-off colors, shadows, radius values, and spacing.

## Token Model
Use semantic tokens first, implemented through CSS variables:

| Semantic Token | Current CSS Alias | Usage |
| --- | --- | --- |
| surface-primary | `--n45-surface` | Cards, menus, modals, forms |
| surface-secondary | `--n45-surface-muted` | Table headers, search fields, subtle panels |
| surface-app | `--n45-bg` | Page background |
| text-primary | `--n45-text` | Main text |
| text-muted | `--n45-muted` | Secondary metadata |
| border-default | `--n45-border` | Controls and major boundaries |
| border-subtle | `--n45-border-soft` | Table rows and section dividers |
| action-primary | `--n45-accent` | Primary action, links, focus |
| action-primary-hover | `--n45-accent-hover` | Hover and active states |
| status-success | `--n45-success` | Complete, healthy, paid |
| status-warning | `--n45-warning` | Due soon, waiting, degraded |
| status-critical | `--n45-danger` | Breach, failed, destructive |

Dark mode must override the same tokens intentionally. Do not invert colors automatically.

## Typography
- Base family: Inter first, then system UI fallbacks already configured in `css/itflow_custom.css`.
- Page titles: compact, 20-24px equivalent.
- Card/panel titles: 14-16px equivalent, bold.
- Table headers: small uppercase labels with strong weight.
- Body text: 14px default in dense operational views.
- Letter spacing: 0 except table header micro-labels.

## Spacing and Density
Support three density modes over time:

| Mode | Use |
| --- | --- |
| Comfortable | Default for broad usability and admin forms. |
| Compact | Default for technician queues and record lists. |
| High density | Optional for dispatch, billing review, and power users. |

No operational page should use large hero treatments or marketing spacing.

## Core Components
Buttons:
Use icon plus text for primary commands and icon-only buttons only when a familiar symbol is sufficient. Icon-only buttons need a title or accessible label.

Forms:
Labels are visible. Validation appears inline plus summary for long forms. Save controls belong at the end of the form or sticky footer when the form is long.

Tables:
Use sticky headers where practical, persisted filters, column visibility, bulk selection, row preview, and keyboard row navigation. Mobile requires purpose-built list views.

Record headers:
Show identity, status, ownership, priority/risk, last activity, and primary actions. Inline status/assignment changes should use POST-backed controls.

Badges:
Every status badge must include text. Color is only supporting information.

Dialogs and drawers:
Dialogs require focus trap, Escape behavior, labelled title, and focus restoration. Use drawers for contextual related-record inspection.

Toasts and alerts:
Use for outcomes, not for required decisions. Destructive or financial consequences need explicit confirmation.

Activity timelines:
Use the same event model for native and integration actions. Avoid dumping raw payloads into the normal timeline.

## Accessibility Baseline
- Visible focus on every interactive control.
- Keyboard navigation for menus, modal dialogs, command palette, and table rows.
- Proper landmarks in the app shell.
- Icon buttons have accessible names.
- Statuses never rely on color alone.
- Reduced motion preference respected for transitions.

