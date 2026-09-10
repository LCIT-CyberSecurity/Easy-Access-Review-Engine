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
    role_permissions: dict[str, list[str]] = {}
    matrix = path.parent / "policy" / "role-permissions.csv"
    if matrix.exists():
        role_permissions = _role_permission_summary(matrix)
        (path / "access-matrix.html").write_text(render_access_matrix(matrix), encoding="utf-8")
        reference_links.append({"label": "Access matrix", "href": "access-matrix.html"})
    (path / "campaign-report.html").write_text(
        render_html_report(campaign, rows, golden_version, reference_links, role_permissions), encoding="utf-8"
    )


def _role_permission_summary(csv_path: str | Path) -> dict[str, list[str]]:
    with Path(csv_path).open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    values: dict[str, set[str]] = {}
    for row in rows:
        values.setdefault(row["role"], set()).add(f"{row['resource']}: {row['permission']}")
    return {role: sorted(items) for role, items in sorted(values.items())}


def render_access_matrix(csv_path: str | Path) -> str:
    path = Path(csv_path)
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    roles = sorted({row["role"] for row in rows})
    resources = sorted({row["resource"] for row in rows})
    permissions = {
        (row["role"], row["resource"]): sorted(
            item["permission"] for item in rows if item["role"] == row["role"] and item["resource"] == row["resource"]
        )
        for row in rows
    }
    head = "".join(f"<th>{escape(role)}</th>" for role in roles)
    body = "".join(
        "<tr>"
        + f"<th>{escape(resource)}</th>"
        + "".join(_matrix_cell(permissions.get((role, resource), [])) for role in roles)
        + "</tr>"
        for resource in resources
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Matrix</title>
<style>
:root {{ --bg:#f7f8fa; --ink:#151a21; --muted:#667085; --line:#d9dee5; --accent:#0f766e; --soft:#e4f5f2; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
main {{ max-width:1400px; margin:0 auto; padding:36px; }}
h1 {{ margin:0; font-size:34px; }}
p {{ color:var(--muted); }}
.matrix {{ margin-top:24px; overflow:auto; background:white; border:1px solid var(--line); border-radius:14px; }}
table {{ border-collapse:collapse; width:100%; min-width:900px; }}
th,td {{ padding:14px; border-bottom:1px solid #edf1f5; border-right:1px solid #edf1f5; text-align:left; vertical-align:top; }}
thead th {{ position:sticky; top:0; background:#fff; z-index:2; color:var(--muted); font-size:12px; text-transform:uppercase; }}
tbody th {{ font-weight:800; background:#fbfcfd; }}
.perms {{ display:flex; gap:6px; flex-wrap:wrap; }}
.perm {{ border-radius:999px; padding:4px 8px; font-size:12px; font-weight:800; background:var(--soft); color:#134e4a; }}
.empty {{ color:#a0a8b2; }}
</style>
</head>
<body><main><h1>Access Matrix</h1><p>Role to resource permissions used as the UAT Golden policy reference.</p><section class="matrix"><table><thead><tr><th>Resource</th>{head}</tr></thead><tbody>{body}</tbody></table></section></main></body></html>"""


def _matrix_cell(values: list[str]) -> str:
    if not values:
        return '<td><span class="empty">-</span></td>'
    content = "".join(f'<span class="perm">{escape(value)}</span>' for value in values)
    return f'<td><div class="perms">{content}</div></td>'


def render_html_report(
    campaign: Campaign,
    rows: list[dict[str, object]],
    golden_version: GoldenSourceVersion | None = None,
    reference_links: list[dict[str, str]] | None = None,
    role_permissions: dict[str, list[str]] | None = None,
) -> str:
    summary = _summary(rows)
    role_permissions_json = (
        json.dumps(role_permissions or {})
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("</", "<\\/")
    )
    data_json = (
        json.dumps(rows)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("</", "<\\/")
    )
    links_html = _reference_links_html(reference_links or [])
    options = {
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
  --bg: #f7f8fa;
  --ink: #151a21;
  --muted: #667085;
  --soft: #eef1f4;
  --line: #d9dee5;
  --accent: #0f766e;
  --accent-soft: #e4f5f2;
  --bad: #b42318;
  --bad-soft: #fff0ef;
  --warn: #a15c07;
  --warn-soft: #fff6e5;
  --ok: #16763b;
  --ok-soft: #ecf8f0;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--bg); color: var(--ink); font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 14px; letter-spacing: 0; }}
.shell {{ max-width: 1500px; margin: 0 auto; padding: 34px 34px 54px; }}
.hero {{ display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 24px; align-items: end; padding: 10px 0 28px; border-bottom: 1px solid var(--line); }}
.kicker {{ color: var(--accent); font-weight: 800; text-transform: uppercase; font-size: 12px; margin: 0 0 10px; }}
h1 {{ margin: 0; font-size: 38px; line-height: 1.05; font-weight: 820; letter-spacing: 0; }}
.subtitle {{ margin: 12px 0 0; color: var(--muted); font-size: 15px; }}
.references {{ display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; }}
.references a {{ color: #075985; background: #e8f5fb; border: 1px solid #c8e6f3; border-radius: 999px; padding: 8px 12px; font-weight: 750; text-decoration: none; }}
.metrics {{ display: grid; grid-template-columns: repeat(6, minmax(120px, 1fr)); gap: 18px; padding: 24px 0; }}
.metric {{ min-width: 0; }}
.metric strong {{ display: block; color: var(--muted); font-size: 12px; font-weight: 760; text-transform: uppercase; }}
.metric span {{ display: block; margin-top: 6px; font-size: 28px; font-weight: 820; }}
.workspace {{ display: grid; grid-template-columns: 250px minmax(0, 1fr); gap: 34px; align-items: start; }}
.sidebar {{ position: sticky; top: 18px; padding-top: 8px; }}
.side-title {{ margin: 0 0 12px; color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; }}
.role-list {{ display: grid; gap: 4px; }}
.role-link {{ border: 0; background: transparent; border-radius: 8px; padding: 9px 10px; text-align: left; cursor: pointer; color: #354052; }}
.role-link:hover, .role-link.active {{ background: var(--accent-soft); color: #134e4a; }}
.role-link b {{ display: block; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.role-link span {{ color: var(--muted); font-size: 12px; }}
.toolbar {{ display: grid; gap: 12px; margin-bottom: 28px; }}
.filters {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; }}
label span {{ display: block; margin-bottom: 6px; color: var(--muted); font-size: 11px; font-weight: 800; text-transform: uppercase; }}
select,input {{ width: 100%; min-height: 40px; border: 1px solid var(--line); border-radius: 9px; background: white; color: var(--ink); padding: 8px 11px; font: inherit; }}
.quick {{ display: flex; flex-wrap: wrap; gap: 8px; }}
.quick button {{ border: 0; background: var(--soft); color: #354052; border-radius: 999px; padding: 8px 12px; font-weight: 760; cursor: pointer; }}
.quick button:hover {{ background: var(--accent-soft); color: #134e4a; }}
.focus {{ display: flex; align-items: center; justify-content: space-between; gap: 18px; margin-bottom: 16px; }}
.focus h2 {{ margin: 0; font-size: 22px; font-weight: 800; }}
.focus p {{ margin: 4px 0 0; color: var(--muted); }}
.counts {{ display: flex; flex-wrap: wrap; gap: 7px; justify-content: flex-end; }}
.pill {{ border-radius: 999px; padding: 5px 9px; font-size: 12px; font-weight: 800; background: var(--soft); color: #475467; }}
.pill.ok {{ background: var(--ok-soft); color: var(--ok); }} .pill.warn {{ background: var(--warn-soft); color: var(--warn); }} .pill.bad {{ background: var(--bad-soft); color: var(--bad); }}
.access-section {{ padding: 26px 0; border-top: 1px solid var(--line); }}
.access-section:first-of-type {{ border-top: 0; padding-top: 0; }}
.access-head {{ display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 18px; align-items: start; margin-bottom: 14px; }}
.access-title {{ margin: 0; font-size: 20px; font-weight: 820; }}
.access-meta {{ margin: 5px 0 0; color: var(--muted); }}
.exceptions {{ margin: 12px 0 16px; padding-left: 14px; border-left: 3px solid var(--bad); color: var(--bad); font-weight: 720; display: grid; gap: 5px; }}
.grants {{ display:flex; flex-wrap:wrap; gap:7px; margin:10px 0 18px; }}
.grant {{ border-radius:999px; padding:5px 9px; background:var(--accent-soft); color:#134e4a; font-weight:760; font-size:12px; }}
.review-list {{ display: grid; gap: 8px; }}
.review-row {{ display: grid; grid-template-columns: minmax(190px, 1.1fr) 130px 130px minmax(150px, 1fr) minmax(170px, 1fr); gap: 14px; align-items: center; padding: 12px 0; border-top: 1px solid #e8edf2; }}
.review-row:first-child {{ border-top: 0; }}
.identity {{ font-weight: 800; }}
.sub {{ color: var(--muted); font-size: 12px; margin-top: 2px; }}
.status {{ display: inline-flex; width: fit-content; border-radius: 999px; padding: 4px 8px; background: var(--soft); color: #475467; font-weight: 760; font-size: 12px; }}
.classification.unexpected, .issue:not(:empty) {{ color: var(--bad); font-weight: 800; }}
.classification.missing {{ color: var(--warn); font-weight: 800; }}
.classification.expected_and_observed {{ color: var(--ok); font-weight: 800; }}
.decision {{ font-weight: 780; }}
.empty {{ padding: 42px 0; color: var(--muted); border-top: 1px dashed var(--line); }}
@media (max-width: 1050px) {{ .workspace {{ grid-template-columns: 1fr; }} .sidebar {{ position: relative; top: auto; }} .metrics {{ grid-template-columns: repeat(2, 1fr); }} .hero, .access-head, .focus {{ grid-template-columns: 1fr; }} .references, .counts {{ justify-content: flex-start; }} .review-row {{ grid-template-columns: 1fr; gap: 6px; }} }}
</style>
</head>
<body>
<div class="shell">
<header class="hero">
  <div><p class="kicker">Access review campaign</p><h1>{escape(campaign.display_name or campaign.name)}</h1><p class="subtitle">Golden Source version: {escape(str(golden_version.version) if golden_version else "none")}</p></div>
  {links_html}
</header>
<section class="metrics">{_summary_html(summary)}</section>
<div class="workspace">
  <aside class="sidebar"><p class="side-title">Roles / Accesses</p><div id="role-list" class="role-list"></div></aside>
  <main>
    <section class="toolbar"><div class="filters">{filters}<label><span>identity</span><input id="filter-identity" placeholder="Search identity"></label><label><span>role / access</span><input id="filter-access" placeholder="Search role or permission"></label><label><span>finding</span><input id="filter-finding" placeholder="Search finding"></label></div><div class="quick"><button type="button" data-classification="">All</button><button type="button" data-classification="unexpected">Unexpected</button><button type="button" data-classification="missing">Missing</button><button type="button" data-classification="expected_and_observed">Expected and observed</button><button type="button" data-access-prefix="CRM-">Roles only</button></div></section>
    <section class="focus"><div><h2 id="focus-title">All review items</h2><p id="focus-subtitle"></p></div><div id="focus-counts" class="counts"></div></section>
    <section id="board"></section>
  </main>
</div>
</div>
<script>
const rows = {data_json};
const rolePermissions = {role_permissions_json};
const filters = ["classification","decision","reviewer"];
function val(id) {{ return document.getElementById(id).value.toLowerCase(); }}
function match(row) {{ for (const f of filters) {{ const v = val("filter-" + f); if (v && String(row[f]).toLowerCase() !== v) return false; }} const identity = val("filter-identity"); if (identity && !String(row.identity).toLowerCase().includes(identity)) return false; const access = val("filter-access"); if (access && !String(row.access).toLowerCase().includes(access)) return false; const finding = val("filter-finding"); if (finding && !String(row.findings).toLowerCase().includes(finding) && !String(row.issue).toLowerCase().includes(finding)) return false; return true; }}
function textEl(tag, value, className) {{ const el = document.createElement(tag); el.textContent = value == null ? "" : String(value); if (className) el.className = className; return el; }}
function summarize(items) {{ const out = {{total: items.length, ok: 0, unexpected: 0, missing: 0, scoped: 0, issues: 0, approve: 0, revoke: 0, pending: 0}}; for (const row of items) {{ if (row.classification === "expected_and_observed") out.ok++; if (row.classification === "unexpected") out.unexpected++; if (row.classification === "missing") out.missing++; if (row.classification === "unknown_due_to_scope") out.scoped++; if (row.issue) out.issues++; if (out[row.decision] != null) out[row.decision]++; }} return out; }}
function groupsFor(items) {{ const groups = new Map(); for (const row of items) {{ if (!groups.has(row.access)) groups.set(row.access, []); groups.get(row.access).push(row); }} return [...groups.entries()].sort((a,b) => a[0].localeCompare(b[0])); }}
function pill(value, kind) {{ return textEl("span", value, "pill " + (kind || "")); }}
function renderSidebar(groups) {{ const nav = document.getElementById("role-list"); nav.replaceChildren(); for (const [access, items] of groups) {{ const s = summarize(items); const btn = document.createElement("button"); btn.className = "role-link"; btn.appendChild(textEl("b", access)); btn.appendChild(textEl("span", s.total + " items · " + s.issues + " issues")); btn.addEventListener("click", () => {{ document.getElementById("filter-access").value = access; render(); }}); nav.appendChild(btn); }} }}
function render() {{ const visible = rows.filter(match); const groups = groupsFor(visible); const total = summarize(visible); renderSidebar(groups); document.getElementById("focus-title").textContent = val("filter-access") || "All review items"; document.getElementById("focus-subtitle").textContent = visible.length + " visible review items"; const counts = document.getElementById("focus-counts"); counts.replaceChildren(pill(total.ok + " ok", "ok"), pill(total.unexpected + " unexpected", "bad"), pill(total.missing + " missing", "warn"), pill(total.issues + " issues", total.issues ? "bad" : "")); const board = document.getElementById("board"); board.replaceChildren(); if (!visible.length) {{ board.appendChild(textEl("div", "No matching review items.", "empty")); return; }} for (const [access, items] of groups) {{ const s = summarize(items); const section = document.createElement("section"); section.className = "access-section"; const head = document.createElement("div"); head.className = "access-head"; const title = document.createElement("div"); title.appendChild(textEl("h3", access, "access-title")); const first = items[0]; title.appendChild(textEl("p", (first.service || "No service") + " / " + first.provider + " / " + (first.control_object_type || "access"), "access-meta")); const badges = document.createElement("div"); badges.className = "counts"; badges.append(pill(s.total + " items"), pill(s.ok + " ok", "ok"), pill(s.unexpected + " unexpected", "bad"), pill(s.missing + " missing", "warn")); head.append(title, badges); section.appendChild(head); const grants = rolePermissions[access] || []; if (grants.length) {{ const grantsEl = document.createElement("div"); grantsEl.className = "grants"; for (const grant of grants) grantsEl.appendChild(textEl("span", grant, "grant")); section.appendChild(grantsEl); }} const issueRows = items.filter(r => r.issue); if (issueRows.length) {{ const ex = document.createElement("div"); ex.className = "exceptions"; for (const row of issueRows) ex.appendChild(textEl("div", row.identity + " · " + row.issue)); section.appendChild(ex); }} const list = document.createElement("div"); list.className = "review-list"; for (const row of items.sort((a,b) => String(a.identity).localeCompare(String(b.identity)))) {{ const line = document.createElement("div"); line.className = "review-row"; const who = document.createElement("div"); who.appendChild(textEl("div", row.identity, "identity")); who.appendChild(textEl("div", row.identity_provider + " · " + row.identity_status, "sub")); line.appendChild(who); line.appendChild(textEl("div", row.classification, "classification " + row.classification)); line.appendChild(textEl("div", "Review: " + row.decision, "decision")); line.appendChild(textEl("div", row.issue, "issue")); line.appendChild(textEl("div", row.findings || row.comment || "", "sub")); list.appendChild(line); }} section.appendChild(list); board.appendChild(section); }} }}
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
    if classification == "missing":
        return "Expected access not observed"
    if classification == "unexpected":
        return "Observed access not expected"
    if classification == "unknown_due_to_scope":
        return "Collection scope incomplete"
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
