from __future__ import annotations

import csv
from dataclasses import asdict
from html import escape
import json
from pathlib import Path

from access_review_engine.domain import Campaign, Decision, GoldenSourceVersion, ReviewItem
from access_review_engine.services import latest_decisions


def build_report_rows(review_items: list[ReviewItem], decisions: list[Decision]) -> list[dict[str, object]]:
    latest = latest_decisions(decisions)
    rows: list[dict[str, object]] = []
    for item in review_items:
        decision = latest.get(item.id)
        target = item.target or {}
        service = (target.get("service") or {}).get("display_name") or (target.get("service") or {}).get(
            "identifier"
        )
        component = (target.get("component") or {}).get("display_name") or (
            target.get("component") or {}
        ).get("identifier")
        rows.append(
            {
                "owner": _owner_label(item.reviewer),
                "service": service or "",
                "component": component or "",
                "provider": item.access_provider,
                "control_object_type": item.control_object.get("type", ""),
                "control_object": item.control_object.get("display_name")
                or item.control_object.get("identifier", ""),
                "permission": item.permission.get("display_name") or item.permission.get("identifier", ""),
                "access": item.access_name,
                "description": item.description or "",
                "identity": item.identity_identifier,
                "identity_provider": item.identity_provider,
                "identity_status": item.identity_status,
                "expected": "yes" if item.expected else "no",
                "observed": "yes" if item.observed else "no",
                "classification": item.classification,
                "findings": ", ".join(item.findings),
                "issue": _issue_label(item.classification, item.findings),
                "decision": decision.value if decision else "pending",
                "reviewer": _owner_label(item.reviewer),
                "comment": decision.comment if decision else "",
            }
        )
    return rows


def write_reports(
    output_dir: str | Path,
    campaign: Campaign,
    review_items: list[ReviewItem],
    decisions: list[Decision],
    golden_version: GoldenSourceVersion | None = None,
) -> None:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    rows = build_report_rows(review_items, decisions)
    (path / "campaign-results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    with (path / "campaign-results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ["campaign"])
        writer.writeheader()
        writer.writerows(_spreadsheet_safe_rows(rows))
    reference_links = []
    matrix = path.parent / "policy" / "role-permissions.csv"
    if matrix.exists():
        reference_links.append({"label": "Access matrix", "href": "../policy/role-permissions.csv"})
    (path / "campaign-report.html").write_text(
        render_html_report(campaign, rows, golden_version, reference_links), encoding="utf-8"
    )


def render_html_report(
    campaign: Campaign,
    rows: list[dict[str, object]],
    golden_version: GoldenSourceVersion | None = None,
    reference_links: list[dict[str, str]] | None = None,
) -> str:
    summary = _summary(rows)
    data_json = (
        json.dumps(rows)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("</", "<\\/")
    )
    links_html = _reference_links_html(reference_links or [])
    options = {
        "service": sorted({str(row["service"]) for row in rows}),
        "provider": sorted({str(row["provider"]) for row in rows}),
        "classification": sorted({str(row["classification"]) for row in rows}),
        "decision": sorted({str(row["decision"]) for row in rows}),
        "reviewer": sorted({str(row["reviewer"]) for row in rows}),
    }
    filters = "".join(
        f'<label><span>{escape(name)}</span><select id="filter-{escape(name)}"><option value="">All</option>'
        + "".join(f'<option value="{escape(value)}">{escape(value) or "Unassigned"}</option>' for value in values)
        + "</select></label>"
        for name, values in options.items()
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Review - {escape(campaign.display_name or campaign.name)}</title>
<style>
:root {{
  color-scheme: light;
  --bg: #eef2f6;
  --shell: #0f1720;
  --shell-2: #182331;
  --panel: #ffffff;
  --panel-soft: #f7f9fb;
  --ink: #111827;
  --muted: #667085;
  --line: #d9e2ec;
  --line-strong: #b8c7d6;
  --brand: #0f766e;
  --brand-2: #155e75;
  --brand-soft: #dff7f3;
  --ok: #15803d;
  --ok-bg: #e7f8ed;
  --warn: #b45309;
  --warn-bg: #fff4dc;
  --bad: #b42318;
  --bad-bg: #feeceb;
  --info: #2563eb;
  --info-bg: #eaf1ff;
  --shadow: 0 18px 45px rgba(15, 23, 32, 0.12);
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  min-height: 100vh;
  background: radial-gradient(circle at top left, #d7f4ee 0, transparent 32rem), var(--bg);
  color: var(--ink);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 14px;
  letter-spacing: 0;
}}
.app {{ display: grid; grid-template-columns: 320px minmax(0, 1fr); min-height: 100vh; }}
aside {{
  background: linear-gradient(180deg, var(--shell), var(--shell-2));
  color: #e5edf5;
  padding: 24px;
  position: sticky;
  top: 0;
  height: 100vh;
  overflow: auto;
}}
.brand {{ display: flex; align-items: center; gap: 12px; margin-bottom: 28px; }}
.logo {{ width: 38px; height: 38px; border-radius: 10px; background: linear-gradient(135deg, #2dd4bf, #38bdf8); box-shadow: 0 12px 25px rgba(45, 212, 191, .25); }}
.brand h1 {{ margin: 0; font-size: 17px; line-height: 1.15; font-weight: 780; }}
.brand p {{ margin: 4px 0 0; color: #9fb0c3; font-size: 12px; }}
.side-section {{ margin-top: 22px; }}
.side-title {{ color: #9fb0c3; font-size: 11px; text-transform: uppercase; font-weight: 760; margin: 0 0 10px; }}
.nav-list {{ display: grid; gap: 8px; }}
.nav-item {{
  width: 100%;
  border: 1px solid rgba(255,255,255,.08);
  background: rgba(255,255,255,.04);
  color: #edf5fb;
  border-radius: 10px;
  padding: 10px 11px;
  text-align: left;
  cursor: pointer;
}}
.nav-item:hover, .nav-item.active {{ background: rgba(45,212,191,.14); border-color: rgba(45,212,191,.45); }}
.nav-name {{ display: block; font-weight: 730; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.nav-meta {{ display: flex; gap: 7px; margin-top: 6px; color: #b7c5d3; font-size: 12px; }}
.content {{ min-width: 0; padding: 28px; }}
.hero {{
  background: rgba(255,255,255,.84);
  border: 1px solid rgba(184,199,214,.8);
  border-radius: 14px;
  box-shadow: var(--shadow);
  padding: 24px;
  margin-bottom: 18px;
}}
.hero-top {{ display: flex; justify-content: space-between; gap: 18px; align-items: flex-start; }}
.hero h2 {{ margin: 0; font-size: 28px; font-weight: 790; }}
.hero p {{ margin: 8px 0 0; color: var(--muted); }}
.references {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }}
.references a {{ color: #075985; background: #e0f2fe; border: 1px solid #bae6fd; border-radius: 999px; padding: 7px 12px; font-weight: 740; text-decoration: none; }}
.references a:hover {{ border-color: #0284c7; }}
.summary {{ display: grid; grid-template-columns: repeat(6, minmax(120px, 1fr)); gap: 12px; margin-top: 20px; }}
.metric {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 14px; }}
.metric strong {{ display: block; color: var(--muted); font-size: 11px; font-weight: 780; text-transform: uppercase; }}
.metric span {{ display: block; margin-top: 7px; font-size: 25px; font-weight: 800; }}
.toolbar {{
  background: rgba(255,255,255,.92);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 14px;
  margin-bottom: 18px;
  position: sticky;
  top: 14px;
  z-index: 4;
  box-shadow: 0 12px 28px rgba(15,23,32,.08);
}}
.filters {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; }}
label span {{ display: block; margin-bottom: 5px; color: var(--muted); font-size: 11px; font-weight: 780; text-transform: uppercase; }}
select,input {{ width: 100%; min-height: 38px; border: 1px solid var(--line-strong); border-radius: 9px; background: #fff; color: var(--ink); padding: 8px 10px; font: inherit; }}
.quick {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }}
.quick button {{ border: 1px solid var(--line); border-radius: 999px; background: #fff; color: #134e4a; padding: 8px 12px; font-weight: 760; cursor: pointer; }}
.quick button:hover {{ border-color: var(--brand); background: var(--brand-soft); }}
.board {{ display: grid; gap: 14px; }}
.access-card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 14px; box-shadow: 0 10px 30px rgba(15,23,32,.08); overflow: hidden; }}
.card-head {{ display: grid; grid-template-columns: minmax(260px, 1fr) auto; gap: 16px; padding: 18px; border-bottom: 1px solid var(--line); }}
.card-title {{ display: flex; align-items: center; gap: 10px; margin: 0; font-size: 18px; font-weight: 790; }}
.role-dot {{ width: 11px; height: 11px; border-radius: 50%; background: var(--brand); box-shadow: 0 0 0 4px var(--brand-soft); flex: 0 0 auto; }}
.card-meta {{ margin-top: 5px; color: var(--muted); font-size: 13px; }}
.badges {{ display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 7px; align-content: flex-start; }}
.badge {{ border-radius: 999px; padding: 5px 10px; font-size: 12px; font-weight: 780; white-space: nowrap; }}
.ok {{ background: var(--ok-bg); color: var(--ok); }} .warn {{ background: var(--warn-bg); color: var(--warn); }} .bad {{ background: var(--bad-bg); color: var(--bad); }} .info {{ background: var(--info-bg); color: var(--info); }} .neutral {{ background: #eef2f6; color: #475569; }}
.exception-strip {{ display: none; gap: 8px; flex-wrap: wrap; padding: 12px 18px; background: #fff7ed; border-bottom: 1px solid #fed7aa; color: #9a3412; font-weight: 720; }}
.access-card.has-issues .exception-strip {{ display: flex; }}
.table-wrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; min-width: 1080px; }}
th {{ background: #f8fafc; color: var(--muted); font-size: 11px; text-align: left; text-transform: uppercase; padding: 11px 12px; border-bottom: 1px solid var(--line); }}
td {{ padding: 12px; border-bottom: 1px solid #edf2f7; vertical-align: top; }}
tr:last-child td {{ border-bottom: 0; }}
tr[data-classification="unexpected"] td {{ background: #fff7f7; }}
tr[data-classification="missing"] td {{ background: #fffaf0; }}
tr[data-classification="unknown_due_to_scope"] td {{ background: #f8fafc; }}
.identity {{ font-weight: 780; }}
.status-pill {{ display: inline-flex; border-radius: 999px; padding: 4px 8px; background: #eef2f6; color: #475569; font-weight: 720; font-size: 12px; }}
.issue {{ color: var(--bad); font-weight: 780; }}
.muted {{ color: var(--muted); }}
.empty {{ background: var(--panel); border: 1px dashed var(--line-strong); border-radius: 14px; padding: 30px; color: var(--muted); }}
@media (max-width: 1100px) {{ .app {{ grid-template-columns: 1fr; }} aside {{ position: relative; height: auto; }} .summary {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }} .card-head, .hero-top {{ grid-template-columns: 1fr; display: grid; }} .badges {{ justify-content: flex-start; }} }}
</style>
</head>
<body>
<div class="app">
<aside>
  <div class="brand"><div class="logo"></div><div><h1>Access Review</h1><p>Campaign control room</p></div></div>
  <div class="side-section"><p class="side-title">Roles and accesses</p><div id="nav-list" class="nav-list"></div></div>
  <div class="side-section"><p class="side-title">Current focus</p><div id="focus-summary" class="nav-meta">All review items</div></div>
</aside>
<div class="content">
<section class="hero">
  <div class="hero-top"><div><h2>{escape(campaign.display_name or campaign.name)}</h2><p>Golden Source version: {escape(str(golden_version.version) if golden_version else "none")}</p></div><div class="badges"><span class="badge neutral" id="visible-count"></span><span class="badge bad" id="issue-count"></span></div></div>
  {links_html}
  <div class="summary">{_summary_html(summary)}</div>
</section>
<section class="toolbar">
  <div class="filters">{filters}<label><span>identity</span><input id="filter-identity" placeholder="Search identity"></label><label><span>role / access</span><input id="filter-access" placeholder="Search role or permission"></label><label><span>finding</span><input id="filter-finding" placeholder="Search finding"></label></div>
  <div class="quick"><button type="button" data-classification="">All</button><button type="button" data-classification="unexpected">Unexpected</button><button type="button" data-classification="missing">Missing</button><button type="button" data-classification="expected_and_observed">Expected and observed</button><button type="button" data-access-prefix="CRM-">Roles only</button></div>
</section>
<section id="board" class="board"></section>
</div>
</div>
<script>
const rows = {data_json};
const filters = ["service","provider","classification","decision","reviewer"];
function val(id) {{ return document.getElementById(id).value.toLowerCase(); }}
function match(row) {{
  for (const f of filters) {{ const v = val("filter-" + f); if (v && String(row[f]).toLowerCase() !== v) return false; }}
  const identity = val("filter-identity"); if (identity && !String(row.identity).toLowerCase().includes(identity)) return false;
  const access = val("filter-access"); if (access && !String(row.access).toLowerCase().includes(access)) return false;
  const finding = val("filter-finding"); if (finding && !String(row.findings).toLowerCase().includes(finding) && !String(row.issue).toLowerCase().includes(finding)) return false;
  return true;
}}
function textEl(tag, value, className) {{ const el = document.createElement(tag); el.textContent = value == null ? "" : String(value); if (className) el.className = className; return el; }}
function pill(value, kind) {{ return textEl("span", value, "badge " + kind); }}
function summarize(items) {{ const out = {{total: items.length, ok: 0, unexpected: 0, missing: 0, scoped: 0, issues: 0, pending: 0, approve: 0, revoke: 0}}; for (const row of items) {{ if (row.classification === "expected_and_observed") out.ok++; if (row.classification === "unexpected") out.unexpected++; if (row.classification === "missing") out.missing++; if (row.classification === "unknown_due_to_scope") out.scoped++; if (row.issue) out.issues++; if (out[row.decision] != null) out[row.decision]++; }} return out; }}
function groupsFor(items) {{ const groups = new Map(); for (const row of items) {{ const key = row.access; if (!groups.has(key)) groups.set(key, []); groups.get(key).push(row); }} return [...groups.entries()].sort((a,b) => a[0].localeCompare(b[0])); }}
function renderNav(groups) {{ const nav = document.getElementById("nav-list"); nav.replaceChildren(); for (const [access, items] of groups) {{ const s = summarize(items); const btn = document.createElement("button"); btn.className = "nav-item"; btn.appendChild(textEl("span", access, "nav-name")); btn.appendChild(textEl("span", s.total + " items · " + s.issues + " issues", "nav-meta")); btn.addEventListener("click", () => {{ document.getElementById("filter-access").value = access; render(); }}); nav.appendChild(btn); }} }}
function render() {{
  const board = document.getElementById("board");
  const visible = rows.filter(match);
  const groups = groupsFor(visible);
  const total = summarize(visible);
  document.getElementById("visible-count").textContent = visible.length + " visible";
  document.getElementById("issue-count").textContent = total.issues + " issues";
  document.getElementById("focus-summary").textContent = val("filter-access") || "All review items";
  renderNav(groups);
  board.replaceChildren();
  if (!visible.length) {{ board.appendChild(textEl("div", "No matching review items.", "empty")); return; }}
  for (const [access, items] of groups) {{
    const s = summarize(items);
    const card = document.createElement("article"); card.className = "access-card" + (s.issues ? " has-issues" : "");
    const head = document.createElement("div"); head.className = "card-head";
    const titleBox = document.createElement("div"); const title = document.createElement("h3"); title.className = "card-title"; title.appendChild(textEl("span", "", "role-dot")); title.appendChild(textEl("span", access)); titleBox.appendChild(title);
    const first = items[0]; titleBox.appendChild(textEl("div", (first.service || "No service") + " / " + first.provider + " / " + (first.control_object_type || "access"), "card-meta"));
    const badges = document.createElement("div"); badges.className = "badges"; badges.appendChild(pill(s.total + " items", "neutral")); badges.appendChild(pill(s.ok + " ok", "ok")); badges.appendChild(pill(s.unexpected + " unexpected", "bad")); badges.appendChild(pill(s.missing + " missing", "warn")); badges.appendChild(pill(s.approve + " approved", "info")); badges.appendChild(pill(s.revoke + " revoke", "bad"));
    head.appendChild(titleBox); head.appendChild(badges); card.appendChild(head);
    const strip = document.createElement("div"); strip.className = "exception-strip"; strip.appendChild(textEl("span", "Findings / exceptions: " + items.filter(r => r.issue).map(r => r.identity + " · " + r.issue).join(" | "))); card.appendChild(strip);
    const wrap = document.createElement("div"); wrap.className = "table-wrap"; const table = document.createElement("table"); const thead = document.createElement("thead"); const hr = document.createElement("tr"); ["Identity","Status","Expected","Observed","Classification","Review decision","Issue","Findings","Reviewer","Comment"].forEach(label => hr.appendChild(textEl("th", label))); thead.appendChild(hr); const tbody = document.createElement("tbody");
    for (const row of items.sort((a,b) => String(a.identity).localeCompare(String(b.identity)))) {{ const tr = document.createElement("tr"); tr.dataset.classification = String(row.classification || ""); const cols = ["identity","identity_status","expected","observed","classification","decision","issue","findings","reviewer","comment"]; for (const key of cols) {{ const cls = key === "identity" ? "identity" : key === "issue" ? "issue" : key === "identity_status" ? "status-pill" : ""; tr.appendChild(textEl("td", row[key], cls)); }} tbody.appendChild(tr); }}
    table.appendChild(thead); table.appendChild(tbody); wrap.appendChild(table); card.appendChild(wrap); board.appendChild(card);
  }}
}}
document.querySelectorAll("select,input").forEach(el => el.addEventListener("input", render));
document.querySelectorAll("button[data-classification]").forEach(el => el.addEventListener("click", () => {{ document.getElementById("filter-classification").value = el.dataset.classification; render(); }}));
document.querySelectorAll("button[data-access-prefix]").forEach(el => el.addEventListener("click", () => {{ document.getElementById("filter-access").value = el.dataset.accessPrefix; render(); }}));
render();
</script>
</body>
</html>"""


def _issue_label(classification: object, findings: list[str]) -> str:
    if findings:
        return ", ".join(str(item) for item in findings)
    if classification in {"unexpected", "missing", "unknown_due_to_scope"}:
        return str(classification)
    return ""


def _reference_links_html(reference_links: list[dict[str, str]]) -> str:
    if not reference_links:
        return ""
    links = "".join(
        f'<a href="{escape(item["href"], quote=True)}">{escape(item["label"])}</a>'
        for item in reference_links
    )
    return f'<nav class="references" aria-label="Reference files">{links}</nav>'


def _summary(rows: list[dict[str, object]]) -> dict[str, int]:
    values = {
        "providers": len({row["provider"] for row in rows}),
        "identities": len({(row["identity_provider"], row["identity"]) for row in rows}),
        "observed": sum(1 for row in rows if row["observed"] == "yes"),
        "expected": sum(1 for row in rows if row["expected"] == "yes"),
    }
    for key in [
        "expected_and_observed",
        "unexpected",
        "missing",
        "unknown_due_to_scope",
        "disabled_with_access",
        "technical_account_without_owner",
        "shared_account_without_owner",
        "approve",
        "revoke",
        "not_applicable",
        "pending",
    ]:
        values[key] = sum(
            1
            for row in rows
            if row["classification"] == key or key in str(row["findings"]) or row["decision"] == key
        )
    return values


def _summary_html(summary: dict[str, int]) -> str:
    return "".join(
        f'<div class="metric"><strong>{escape(key)}</strong><br>{value}</div>'
        for key, value in summary.items()
    )


def _owner_label(owner: object | None) -> str:
    if owner is None:
        return ""
    data = asdict(owner)  # type: ignore[arg-type]
    return f"{data['provider']}/{data['identity']}"


def _spreadsheet_safe_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {key: _spreadsheet_safe(value) for key, value in row.items()}
        for row in rows
    ]


def _spreadsheet_safe(value: object) -> object:
    if not isinstance(value, str):
        return value
    return "'" + value if value.startswith(("=", "+", "-", "@")) else value
