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
        writer.writerows(rows)
    (path / "campaign-report.html").write_text(
        render_html_report(campaign, rows, golden_version), encoding="utf-8"
    )


def render_html_report(
    campaign: Campaign, rows: list[dict[str, object]], golden_version: GoldenSourceVersion | None = None
) -> str:
    summary = _summary(rows)
    data_json = json.dumps(rows).replace("</", "<\\/")
    options = {
        "owner": sorted({str(row["owner"]) for row in rows}),
        "service": sorted({str(row["service"]) for row in rows}),
        "provider": sorted({str(row["provider"]) for row in rows}),
        "classification": sorted({str(row["classification"]) for row in rows}),
        "decision": sorted({str(row["decision"]) for row in rows}),
    }
    filters = "".join(
        f'<label>{escape(name)}<select id="filter-{escape(name)}"><option value="">All</option>'
        + "".join(f'<option value="{escape(value)}">{escape(value)}</option>' for value in values)
        + "</select></label>"
        for name, values in options.items()
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
</header>
<section class="summary">{_summary_html(summary)}</section>
<section>{filters}<label>identity<input id="filter-identity"></label><label>finding<input id="filter-finding"></label></section>
<section id="grouped"></section>
<script>
const rows = {data_json};
const filters = ["owner","service","provider","classification","decision"];
function val(id) {{ return document.getElementById(id).value.toLowerCase(); }}
function match(row) {{
  for (const f of filters) {{
    const v = val("filter-" + f);
    if (v && String(row[f]).toLowerCase() !== v) return false;
  }}
  const identity = val("filter-identity");
  if (identity && !String(row.identity).toLowerCase().includes(identity)) return false;
  const finding = val("filter-finding");
  if (finding && !String(row.findings).toLowerCase().includes(finding)) return false;
  return true;
}}
function render() {{
  const out = document.getElementById("grouped");
  const visible = rows.filter(match);
  let html = "";
  let current = "";
  for (const row of visible) {{
    const group = row.owner + " / " + row.service + " / " + row.access;
    if (group !== current) {{
      if (current) html += "</tbody></table>";
      current = group;
      html += `<h2>Owner: ${{row.owner || "unassigned"}}</h2><h3>Service: ${{row.service || "none"}} - Access: ${{row.access}}</h3>`;
      html += "<table><thead><tr><th>Identity</th><th>Status</th><th>Expected</th><th>Observed</th><th>Classification</th><th>Findings</th><th>Decision</th><th>Reviewer</th><th>Comment</th></tr></thead><tbody>";
    }}
    html += `<tr data-classification="${{row.classification}}"><td>${{row.identity}}</td><td>${{row.identity_status}}</td><td>${{row.expected}}</td><td>${{row.observed}}</td><td>${{row.classification}}</td><td>${{row.findings}}</td><td>${{row.decision}}</td><td>${{row.reviewer}}</td><td>${{row.comment || ""}}</td></tr>`;
  }}
  if (current) html += "</tbody></table>";
  out.innerHTML = html || "<p>No matching rows.</p>";
}}
document.querySelectorAll("select,input").forEach(el => el.addEventListener("input", render));
render();
</script>
</body>
</html>"""


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
