# EARE WebUI — UX / product audit

Audited revision: `webui-improvement` @ `47c70d5`. Audit only: no code, domain model or API was changed.

## Method

1. Traced every WebUI journey through the React code (`web/src/App.tsx`, `web/src/projections.ts`) and the API it calls (`api.py`, `web_read_models.py`, `web_use_cases.py`, `system_admin.py`, `services.py`, `storage.py`).
2. Verified the findings empirically on the integration VM, on an isolated stack built from `47c70d5` (separate containers, volume and port; the regular `web/compose.yaml` deployment was not touched), seeded with `integration.db` (`nexa-crm`) and the `fixtures/raw/active-directory/standard` extract imported as `corp-ad`.

Legend: **✔ verified** on the running stack · *code* = established from code reading only.

Finding types: **UX GAP** (capability exists, UX missing/poor) · **UI GAP** (API exists, not exposed) · **API GAP** (small API operation needed, no domain change) · **CORE GAP** (needs domain change, not solved here) · **POLISH**.
Priorities: **P0** blocks/damages a normal workflow · **P1** professional MVP · **P2** worthwhile · **P3** later.

---

## Overall verdict

**Maturity:** advanced prototype. The target information architecture is in place and role-based navigation works, but several core journeys are broken or empty with real data, and many screens expose implementation data (UUIDs, JSON objects, internal codes) instead of answering the user's question.

**Strong points**

- Correct sectioning (Overview / Access & Reference / Audit / System); Sources & IdPs vs Authentication are clearly separated and SSO is not presented as active.
- Sound backend safeguards: stale Golden comparison is rejected (409 ✔), campaigns with pending items cannot be closed, provider-scoped snapshots cannot be promoted over a multi-provider Golden Source (✔), forced password change on bootstrap, append-only decisions, audit events.
- Calm, consistent CSS token base.

**Main weaknesses**

- Silent failures: most mutations have no error handling (campaign create/open, lifecycle CTAs, Golden baseline/compare/confirm).
- Raw technical data in tables and drawers; hard-coded or fake values ("API connected", "Origin: Baseline / Campaign promotion", static breadcrumb, "Why: Effective provenance").
- `Status` renders no variant/dot: every status looks identical although the CSS defines tones.
- No shared confirmation, toast or contextual empty-state patterns.

---

## Top gaps

### 1. Campaign preview/open crashes when an owned account holds access — P0 · API GAP (bug) · S · ✔

- `storage.hydrate_identity` returns `account_owner` as a `dict`; `services.validate_owner` expects `OwnerRef` → `AttributeError`, HTTP 500 on `POST /api/campaigns/preview` (and the same path on open) for the `nexa-crm` snapshot, whatever the scope.
- The WebUI swallows the error: "Preview campaign" does nothing. New campaigns cannot be created on this data.

### 2. Remediation actions are never generated — P0 · API GAP · S · ✔

- No route persists `services.remediation_from_decisions`. Closing a campaign containing a revoke decision created **0** actions. Actions / My Actions are always empty; BUSINESS_ADMIN has no usable workflow.
- Recommended: generate actions when a campaign is closed and link them from the campaign ("N actions generated → View actions"). Keep the existing `pending` / `exported` statuses.

### 3. Golden Source becomes a dead end with more than one source — P0 (multi-source) · API GAP + CORE question · M · ✔

- Snapshots contain only the synchronized provider (`application.py:166-171`). After importing `corp-ad`, `GET /golden-sources/{name}/compare` raises the domain guard "Cannot promote provider-scoped snapshot over a Golden Source containing other providers" uncaught → HTTP 500. No data loss, but no way forward.
- Recommended: return 409 with a human message; offer provider-scoped comparison. **CORE question:** how a multi-provider Golden Source is meant to be refreshed from provider-scoped snapshots.

### 4. Review drawer does not support a confident decision — P0 · UX GAP + API GAP · M · ✔

- Title "Review item"; no identity, access, permission, target, description, findings, owners, campaign or current decision.
- WHY is always "Provenance not available": review items have `origin=None` and no `paths`/`direct` (✔).
- A failed decision overwrites the reason textarea with "Decision failed" and hides the API message (e.g. 409 "Decisions are only allowed for open campaigns" ✔).
- Recommended: WHO / WHAT / WHY (direct or path computed with `calculate_effective_accesses` on the campaign snapshot) / STATE with a sentence / FINDINGS / CURRENT DECISION.

### 5. Silent mutation failures — P0 · UX GAP · M · code

- Missing `onError` on campaign create/open, campaign CTAs, Golden baseline/compare/confirm. If open fails after the draft is created, retrying creates a duplicate draft.
- Recommended: one mutation wrapper (toast on success/failure, inline form errors, human message + collapsible technical detail, pending buttons).

### 6. Campaign lifecycle CTAs broken or unsafe — P0 · UX GAP · M · ✔

- Buttons show raw keys (`open`, `cancel`, `close-disabled`, `promote`, `report`).
- `report` calls `POST /api/campaigns/{id}/report` → 404 ✔.
- `cancel` / `promote` have no confirmation; promote is repeatable (two clicks → versions 1 → 3 ✔).
- Detail endpoint caps review items at 500; overview shows snapshot/version UUIDs; approved/revoked/N/A counts are projected but not shown.
- Recommended: status stepper (Draft → Open → Closed → Promoted), one contextual primary action with confirmation and impact preview, "Promoted to vN" state, single report menu.

### 7. New campaign produces wrong campaigns — P0 · UX GAP · M · ✔ / code

- "Provider(s)" scope has no provider picker → `values: []` → 0 review items ✔.
- Snapshot/Golden defaults take `[length-1]` of lists sorted by UUID (`web_read_models.py:98`), not the newest/active one (*code*; not reproduced with two snapshots by chance).
- Snapshot label always "assignments unavailable" ✔; unresolved reviewer list returned by the API is not displayed; `default_reviewer`, `manager`, `description` are not exposed (UI GAP); preview is not invalidated on form change; draft save requires accepting unresolved reviewers.

### 8. Landing broken for GROUP_OWNER and BUSINESS_ADMIN — P0 · UX GAP · S · ✔

- `/` always renders Overview; `/api/dashboard` returns 403 for these roles ✔ and the error is ignored, so they see zeros on a page absent from their menu.
- Recommended: redirect `/` to `roleHome(role)`; redirect to login on 401.

### 9. My Reviews is not a work queue — P1 (pending filter: P0 quick fix) · UX GAP · M/L · ✔

- `status=pending` returns 0 while 22 items are undecided ✔ (`web_read_models.py:95` compares against `None`).
- Campaign filter lists UUIDs and is empty for GROUP_OWNER (403 ✔); filters do not reset pagination; pending-first sort only applies to the current page; auto-advance stops at page end; no progress, keyboard shortcuts or bulk actions.
- For ADMIN/OPERATOR, "My Reviews" lists every item of every campaign.

### 10. Users & permissions lifecycle buried and unsafe — P1 · UI GAP + API GAP · M · ✔

- Disable/enable is an "Enabled" checkbox; reset password is a field in the edit form.
- Editing a user without typing a password clears `must_change_password` ✔.
- A disabled user keeps a working session (stateless 8 h cookie) ✔.
- An admin can demote their own / the last ADMIN account ✔.
- Scopes are free text with role-dependent, unexplained effects; nothing explains that a GROUP_OWNER username must match the reviewer identity in the source.

### 11. Identity / Access / Findings investigation shows wrong data — P1 · UX GAP + API GAP · M · ✔

- Access list: `permission` and `target` are objects rendered as JSON; `assignment_count` / `finding_count` are not projected, so Holders/Findings are always 0 ✔.
- Identity drawer lists each direct access twice (Direct and Effective) ✔; State is hard-coded "observed".
- Multi-source: `alice.martin` (`nexa-crm`) shows 1 access in the list but 0 in the drawer after `corp-ad` was imported ✔.
- Filters: `user` never matches `user_account`; hard-coded `openldap` / `active_directory` never match provider names ✔.
- Findings lists every comparison row of the latest snapshot only: after the `corp-ad` import, 11 rows, all `no_reference`, only `corp-ad`, 7 with actual findings ✔; no campaign id ✔; Overview says "Findings 0" ✔.

### 12. Sources health and job feedback — P1 · UX GAP + API GAP · M · ✔

- Health/last sync come from the latest global snapshot: after the `corp-ad` import, `nexa-crm` shows "never synced", 0 identities ✔.
- Cards only exist for sources with a connector file; imported providers without one are invisible ✔.
- The failed job error ("Anonymous OpenLDAP export requires ALLOW_ANONYMOUS=1" ✔) is not displayed; test connection only returns "Source connection test failed" (502 ✔); failed syncs are not audited ✔.
- Job panel: static text, raw JSON result, infinite polling, cards not refreshed; test/save messages render behind the drawer overlay, success in error red. OPERATOR sees Configure but saving is ADMIN-only.

### 13. Audit trail is raw — P1 · UX GAP + API GAP · M · ✔

- Oldest events first ✔; raw event types, ISO dates, `object_type / uuid`, JSON details; page-size selector is a no-op.
- Logins are not recorded ✔; user creation, disable and password reset all appear as `system.user_upserted` ✔.
- No search/filters in the API.

---

## Screen notes

| Screen | Additional notes | Prio |
|---|---|---|
| Global shell | Static breadcrumb and "EARE" eyebrow on every page; always-green "API connected"; raw role; no self-service password change (API exists → UI GAP); icons reused (`Check` ×4); "My Actions" and "Actions" highlighted together (NavLink ignores `?view=my`) and render the same page | P1 |
| Overview | Metrics not clickable; `attention` always empty; `campaigns` and `latest_snapshot` returned but unused; counts capped at 500 rows. Recommended: Needs attention, open campaigns, source health, first-run checklist | P1 |
| Golden Source | "Origin" hard-coded; no version history although provenance fields exist; diff mixes added/removed/unchanged; confirm without summary; CSV export API not exposed; developer copy ("Compare mutates nothing…") | P1 |
| Campaigns list | No status filter, raw due date, scope values hidden, full page reload on "New campaign" | P2 |
| Actions | Drawer omits action type; decision comment not projected (always "—"); no CSV export or "mark exported" (API GAP) | P1 |
| Reports | Defaults to first campaign by name (even drafts); no status/descriptions; duplicate broken CTA in campaign detail | P2 |
| Authentication | Correct separation. Add effective local rules (12-char minimum, forced change, 8 h session) and a greyed "SSO — Planned" card; `POST /system/identity-providers` exists without UI | P2 |

---

## Admin user lifecycle

| Question | Answer | Why |
|---|---|---|
| Create a user? | YES | Complete form; admin-set password forces change |
| Edit a user? | PARTIAL | Clears pending password change when no password is typed ✔ |
| Disable/suspend? | PARTIAL | Checkbox in edit form, no confirmation, no self/last-admin guard ✔, session stays valid ✔ |
| Re-enable? | PARTIAL | Same checkbox |
| Reset/set password? | PARTIAL | Field in edit form; existing sessions not revoked; audit event indistinct ✔ |
| Change role? | PARTIAL | Works; no last-admin guard ✔; ADMIN scopes silently forced to `*`; effective only at next login |
| Change scopes? | PARTIAL | Free text, not validated against sources; semantics differ per role |
| Understand roles? | NO | No descriptions |
| Understand disable consequences? | NO | Nothing about pending reviews, history, or active sessions |

No delete action should be added: disabling preserves attribution.

---

## Cross-cutting recommendations

- **Status:** one `StatusBadge` with label and tone mapping (success / warning / danger / neutral / info).
- **Tables:** whole-row click, formatters (date, role, access target, finding code, event type), useful sorting, truncation with tooltip, "no data" vs "no match" empty states.
- **Filters:** options from data (providers, campaign names), active chips + clear, reset page on every filter change, state in URL.
- **Drawers:** `role="dialog"`, Escape, focus management, labelled close button, fixed footer, internal back stack instead of stacked drawers.
- **Feedback:** toaster in the shell (`aria-live`), mutation wrapper, inline form errors, human messages with collapsible technical detail.
- **Confirmations** only where consequences justify them: open/close/cancel/promote campaign, confirm Golden version, disable user, reset password, bulk approve (light confirmation for sync).
- **Frontend code:** `App.tsx` and `projections.ts` are committed minified (40 KB on 65 lines); reformat, then split into `features/*` and shared `components/ui`, add typed API resources. No framework change.

---

## Backlog

### Phase 1 — blockers

| # | Item | Type | Size |
|---|---|---|---|
| 1.1 | Reformat `App.tsx` / `projections.ts` (no behaviour change) | Code | S |
| 1.2 | Hydrate `account_owner` as `OwnerRef`; return 409 instead of 500 on multi-provider Golden compare | API GAP | S |
| 1.3 | Persist remediation actions on campaign close | API GAP | S |
| 1.4 | Mutation wrapper, toasts, inline errors, no duplicate drafts | UX GAP | M |
| 1.5 | Role landing redirect, 401 → login | UX GAP | S |
| 1.6 | Review drawer context and computed WHY | UX + API GAP | M |
| 1.7 | New campaign: correct defaults, provider picker, stale preview, visible errors | UX GAP | M |
| 1.8 | Campaign CTAs: labels, contextual primary action, confirmations, no broken report, no repeat promote | UX GAP | M |
| 1.9 | Pending filter (API), pagination reset, campaign names in filters | UX + API GAP | S |

### Phase 2 — professional MVP

| # | Item | Type | Size |
|---|---|---|---|
| 2.1 | Users: dedicated disable/enable/reset actions, guards, `must_change_password` fix, role help, scope picker, session revalidation | UI + API GAP | M |
| 2.2 | My Reviews queue: assigned/open/pending default, progress, queue-wide auto-advance, completion, shortcuts | UX GAP | M |
| 2.3 | Golden Source: real provenance, history, tabbed diff, confirm dialog, CSV export, provider-scoped comparison | UX + UI + API GAP | M |
| 2.4 | Actions: labels, complete drawer, CSV export, mark exported | UX + API GAP | M |
| 2.5 | Findings computed against the active Golden version, findings-only default, business labels, pivots | API + UX GAP | M |
| 2.6 | Access/Identities: real counts, formatters, deduplicated direct/inherited, paths, in-drawer pivots, multi-source consistency | UX + API GAP | M |
| 2.7 | Sources: per-provider health and last sync, in-card progress, readable errors (job and connection test), refresh, OPERATOR permissions, audit failed syncs | UX + API GAP | M |
| 2.8 | Audit trail: newest first, labels, links, filters, login events, distinct user events | UX + API GAP | M |
| 2.9 | `StatusBadge`, `Drawer`, `Table` shared components | POLISH | M |
| 2.10 | Operational Overview | UX + UI GAP | M |
| 2.11 | Split frontend into features and shared components | Code | M |

### Phase 3 — premium polish

Real breadcrumb and section eyebrow, user menu with password change, distinct icons (S) · contextual empty states (S) · skeletons and button spinners (S) · formatted dates and concept tooltips (S) · Reports descriptions and unified menu (S) · Authentication rules card (S) · sortable columns and URL filters (M) · accessibility fixes (S).

### Phase 4 — later

Bulk approval with safeguards (M) · draft campaign editing API (M) · reviewer breakdown and reminders (M) · disable/remove source, sync history (M) · last login, lockout, session revocation (M) · review reassignment, to be assessed against the model (L).

## CORE gaps (not addressed)

- Remediation statuses limited to `pending` / `exported` (no done/verified tracking).
- BUSINESS_ADMIN scope is per provider, not per application/target.
- Refreshing a multi-provider Golden Source from provider-scoped snapshots.
