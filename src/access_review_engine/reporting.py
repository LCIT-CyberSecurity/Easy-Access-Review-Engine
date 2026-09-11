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
    data_json = (
        json.dumps(rows)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("</", "<\\/")
    )
    options = {
        "owner": sorted({str(row["owner"]) for row in rows}),
        "service": sorted({str(row["service"]) for row in rows}),
        "provider": sorted({str(row["provider"]) for row in rows}),
        "classification": sorted({str(row["classification"]) for row in rows}),
        "decision": sorted({str(row["decision"]) for row in rows}),
        "reviewer": sorted({str(row["reviewer"]) for row in rows}),
    }
    filters = "".join(
        f'<label>{escape(name)}<select id="filter-{escape(name)}"><option value="">All</option>'
        + "".join(f'<option value="{escape(value)}">{escape(value) or "Unassigned"}</option>' for value in values)
        + "</select></label>"
        for name, values in options.items()
    )
    references = "".join(
        f'<a href="{escape(item["href"], quote=True)}">{escape(item["label"])}</a> '
        for item in reference_links or []
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Access Review - {escape(campaign.display_name or campaign.name)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 24px; color: #17202a; }}
header {{ border-bottom: 1px solid #ccd1d1; margin-bottom: 16px; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 8px; }}
.metric {{ border: 1px solid #d5dbdb; border-radius: 6px; padding: 8px; background: #f8f9f9; }}
label {{ display: inline-flex; flex-direction: column; margin: 0 8px 8px 0; font-size: 12px; }}
select,input {{ min-width: 150px; padding: 6px; }}
button {{ margin: 0 8px 8px 0; padding: 6px 10px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
th,td {{ border-bottom: 1px solid #e5e8e8; text-align: left; padding: 6px; vertical-align: top; }}
tr[data-classification="unexpected"] {{ background: #fff5f5; }}
tr[data-classification="missing"] {{ background: #fffaf0; }}
tr[data-classification="expected_and_observed"] {{ background: #f7fff7; }}
h2 {{ margin-top: 24px; }}
</style>
</head>
<body>
<header>
<h1>Access Review - {escape(campaign.display_name or campaign.name)}</h1>
<p>Golden Source version: {escape(str(golden_version.version) if golden_version else "none")}</p>
<p>{references}</p>
</header>
<section class="summary">{_summary_html(summary)}</section>
<section>{filters}<label>identity<input id="filter-identity"></label><label>access<input id="filter-access"></label><label>finding<input id="filter-finding"></label></section>
<p><button type="button" data-classification="">All</button><button type="button" data-classification="unexpected">Unexpected</button><button type="button" data-classification="missing">Missing</button><button type="button" data-classification="expected_and_observed">Expected and observed</button><button type="button" data-access-prefix="CRM-">Roles only</button></p>
<section id="grouped"></section>
<script>
const rows = {data_json};
const filters = ["owner","service","provider","classification","decision","reviewer"];
function val(id) {{ return document.getElementById(id).value.toLowerCase(); }}
function match(row) {{ for (const f of filters) {{ const v = val("filter-" + f); if (v && String(row[f]).toLowerCase() !== v) return false; }} const identity = val("filter-identity"); if (identity && !String(row.identity).toLowerCase().includes(identity)) return false; const access = val("filter-access"); if (access && !String(row.access).toLowerCase().includes(access)) return false; const finding = val("filter-finding"); if (finding && !String(row.findings).toLowerCase().includes(finding) && !String(row.issue).toLowerCase().includes(finding)) return false; return true; }}
function textEl(tag, value) {{ const el = document.createElement(tag); el.textContent = value == null ? "" : String(value); return el; }}
function render() {{ const out = document.getElementById("grouped"); out.replaceChildren(); const visible = rows.filter(match); let current = ""; let tableBody = null; for (const row of visible) {{ const group = row.owner + " / " + row.service + " / " + row.access; if (group !== current) {{ current = group; out.appendChild(textEl("h2", "Owner: " + (row.owner || "unassigned"))); out.appendChild(textEl("h3", "Service: " + (row.service || "none") + " - Access: " + row.access)); const table = document.createElement("table"); const thead = document.createElement("thead"); const header = document.createElement("tr"); ["Identity","Status","Expected","Observed","Classification","Findings","Decision","Reviewer","Comment"].forEach(value => header.appendChild(textEl("th", value))); thead.appendChild(header); table.appendChild(thead); tableBody = document.createElement("tbody"); table.appendChild(tableBody); out.appendChild(table); }} const tr = document.createElement("tr"); tr.dataset.classification = row.classification; ["identity","identity_status","expected","observed","classification","findings","decision","reviewer","comment"].forEach(key => {{ const td = document.createElement("td"); td.textContent = row[key] == null ? "" : String(row[key]); tr.appendChild(td); }}); tableBody.appendChild(tr); }} if (!visible.length) out.appendChild(textEl("p", "No matching rows.")); }}
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
