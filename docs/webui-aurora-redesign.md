# WebUI review — Aurora redesign

Branch: `feat/webui-aurora-redesign`. Reviewed revision: `main` @ `d3407b2`.
Preview stack: <http://192.168.1.5:4175> (isolated, see *Running the preview* below).

This note records what the review of the WebUI found, what the redesign changes
and what it deliberately leaves alone. It complements `docs/webui-ux-audit.md`,
which covers product and workflow gaps; this one covers the interface itself.

---

## What the review found

### 1. The stylesheet had become a stack of patches — the root problem

`web/src/styles.css` was 820 dense lines in which the same selector was
redefined three or four times as successive passes were appended:

| Selector | Defined at (old file) |
| --- | --- |
| `.login-card` | lines 96, 154, 404, 457 |
| `.table-wrap` | lines 30, 144, 193, 494 |
| `.drawer-section` | lines 234, 316 |
| `td` | lines 30, 146, 191 |
| `.eyebrow` | lines 20, 56 |

Which declaration won depended on source order, so a change in one place could
be silently cancelled somewhere below. Literal colours (`#fafbff`, `#f8faff`,
`#596579`, `rgba(255,255,255,.82)` …) were spread through the component rules
rather than named once, which is why a dark interface could not be added: there
was no single place to change.

### 2. Each interface style re-stated the whole product

`violet`, `azure` and `studio` were not palettes but ~60–100 selector overrides
each (`:root[data-theme="violet"] .panel`, `… .metric`, `… th`, `… .button` …).
Every new component had to be re-styled three more times or it silently fell
back to the default look.

### 3. No dark interface at all

A governance console is a tool people keep open all day. The product offered
four light styles and no dark one, and could not gain one without (2) above
being fixed first.

### 4. The breadcrumb was a constant

The top bar always rendered `Workspace › Access governance`, whatever page was
open — noted as a defect in the UX audit and still present.

### 5. Loading and empty states jumped the page

A loading table rendered a single centred word, so the page re-laid out when the
rows arrived. `.pagination` had no styling at all: the pager rendered as
unaligned inline text under every list.

### 6. Smaller defects

- The sign-in card rendered `WELCOME BACK` as an eyebrow immediately above the
  `Welcome back` heading — the same words twice.
- The window behind the sign-in panel showed the application's light canvas
  under the dark panel at some viewport heights.
- Section headings were stored shouted in the catalogues (`ACCESS & REFERENCE`),
  so any other use of them shouted too.
- The whole application shipped as one 666 kB chunk: every release made every
  visitor re-download React.

---

## What the redesign does

### One stylesheet, three ordered layers

```
1. TOKENS      the only place a colour, radius, shadow or duration is written
2. COMPONENTS  uses tokens only — no literal colour is allowed here
3. THEMES      an interface style is a token set, nothing more
```

Because the component layer names no colour, a style or an appearance never has
to restate a component. The four styles are now ~20 token declarations each
instead of ~100 selector overrides, and both appearances come from the same
component code. The class vocabulary is unchanged, so every screen keeps
working: no JSX had to be rewritten to adopt it.

Result: 820 dense lines → 2 083 readable ones (one declaration per line, every
rule grouped under the section it belongs to), while the *built* stylesheet goes
from **81.4 kB → 74.2 kB** — smaller despite gaining a whole second appearance
and a fifth style, because the duplication is gone.

### Blue, the default style

The product's blue accent (`#2545d3`, as on `main`) over cool neutrals, one focus ring token applied to every control, softer and more
consistent elevation, tabular figures in every data column, and Inter's
alternate glyph set (`cv11`, `ss01`, `cv05`) which reads better in long columns
of counts.

`azure`, `violet` and `studio` are kept and were rebuilt as token sets; `studio`
also keeps its tighter geometry, which is now stated once rather than per
component.

### A real dark appearance

Light / Dark / Follow the system, chosen in the account menu, stored per browser
and resolved before the first paint so it never flashes. Dark is *authored*, not
inverted: the canvas recedes, surfaces lift, and depth comes from lighter edges
because a shadow reads as nothing on a dark field. All four styles have a dark
token set. While "follow the system" is selected, the page follows it live.

### Command palette

`Ctrl/⌘ + K` from anywhere opens a palette listing every page the signed-in
account may open, filtered by role exactly as the rail is. It navigates only —
nothing in it mutates data. Arrow keys move, `Enter` opens, `Esc` closes.

### Corrections

- The breadcrumb now reads the actual route, including nested pages
  (`Audit › Campaigns › Campaign`).
- Tables load as skeleton rows shaped like the data they replace, with the
  loading word kept for screen readers.
- `.pagination` is styled: the count sits left, the controls right.
- The sign-in card no longer repeats `WELCOME BACK` as an eyebrow above the
  `Welcome back` heading; the window behind the sign-in panel matches it. The
  sign-in keeps the LCIT navy composition of `main`.
- Section headings are stored as words and shouted by CSS in the rail only.
- Every rail entry has its own icon (reviews, campaigns and actions no longer
  share a check mark; users and audit trail no longer reuse other glyphs).
- Page titles drop the `EARE` eyebrow: the breadcrumb already names the section.
- Introductory prose is held to a 76-character measure on wide screens.
- Empty states open on an accent glyph and lead with a primary action.
- The rail uses the LCIT mark without its tagline (`lcit-mark.png`), which was
  unreadable at that size; sign-in keeps the full logo.
- Disabled pagination buttons stay legible instead of fading to near-invisible.
- A row of actions under a table or a sentence keeps its distance from it.
- The LCIT mark gets a plate on the dark rail instead of disappearing into it.
- The bundle is split: 666 kB in one chunk → 316 kB of application over a
  cacheable 238 kB vendor chunk, so a release no longer re-ships React.

### Density

Type is one step larger everywhere (16px body; every size from 10px to 15px went
up by 1px), table cells read at 15px with the first column in primary ink, and
rows are taller (20×24px cells). The rail is 280px; its links grow from 44px to
58px and the LCIT mark with "EARE / Access governance" leads it. Spacing is
looser: 36px under the page title, 32px after the introduction, 24px between
toolbar, cards and panels. Gutters scale from 24px to 48px; the content column
stops at 1840px.

### Tables as one unit

- The pagination is the table card's footer; with a single page it only states
  the count.
- Page-level actions (the remediation CSV export) sit at the end of the toolbar.
- The search box is one field, not a box inside a box.
- Sort carets appear on hover, focus, or on the sorted/filtered column only.
- Tables drop tabular figures: Inter widens the hyphen with them.
- A destructive row action (Delete) stays quiet until pointed at.

### Reports and settings pages

- Reports: the four download formats are one joined control; "Open full report"
  is the primary action. Campaign choice and comparison share one toolbar.
- Report figures are one strip divided into columns instead of nine cards.
- Reviewer coverage and opened/closed dates are shown as text, not raw JSON/ISO.
- Section titles no longer carry the prose `h3` top margin inside their card.
- Stacked panels keep 16px between them; authentication methods put the title
  and its status on one line.

### Business permissions

A Golden access may carry several business permissions (`read, write, execute`).
The Golden table and the access drawer edit them as a set of toggles and store
them as one comma-separated value, so the API is unchanged.

### Several applications per access

An access may belong to several applications. In the Golden table and the access
drawer the application field is a type-ahead picker: chosen applications are
removable chips, typing filters a catalogue of any size (40 matches shown, then
"keep typing"), Enter adds, Backspace removes the last chip, and an unknown name
can be created in place. The value is stored as one comma-separated list; the
API splits it (`split_multi_value`) wherever it counts, lists or matches
applications, so the payload shape is unchanged.

### System database connections

The API used one SQLite connection for the system tables across FastAPI's worker
threads; concurrent reads interleaved and returned incomplete rows, which showed
as random 500s and sign-outs. Each worker thread now gets its own connection.

### Accessibility and RTL

One focus-ring token on every interactive element; `prefers-reduced-motion`
disables every animation added here; every status badge still carries a dot, so
no state is signalled by colour alone; RTL mirrors the rail marker, the drawer
edge, the sticky action column and the accent borders.

---

## What this branch does not change

No domain model, no API call, no route, no permission, no workflow. The gaps
listed in `docs/webui-ux-audit.md` (remediation actions never generated, review
drawer provenance, silent mutation failures, campaign lifecycle CTAs …) are
product work and are untouched here.

---

## Running the preview

The preview stack is deliberately separate from the integration deployment on
4173: its own compose project, container names, port and data volume.

```bash
cp .env.example .env            # set EARE_SESSION_SECRET / EARE_ADMIN_PASSWORD
docker compose -f docker/compose.aurora.yaml up -d --build
```

| | Integration (unchanged) | Aurora preview |
| --- | --- | --- |
| Port | 4173 | **4175** |
| Containers | `eare-api`, `eare-webui` | `eare-aurora-api`, `eare-aurora-webui` |
| Images | `eare-api:python312`, `eare-webui:nginx` | `eare-api:aurora`, `eare-webui:aurora` |
| Volume | `eare-data` | `eare-aurora-data` |

To stop it without touching anything else:

```bash
docker compose -f docker/compose.aurora.yaml down
```
