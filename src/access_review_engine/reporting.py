from __future__ import annotations

import csv
from dataclasses import asdict
from datetime import UTC, datetime
from html import escape
import json
from pathlib import Path

from access_review_engine.authentication import compare_authentication_posture
from access_review_engine.domain import AuthenticationPosture, Campaign, Decision, GoldenSourceVersion, ReviewItem
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
    authentication_posture: AuthenticationPosture | None = None,
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
        matrix_auth = (
            [_authentication_posture_policy(golden_version.golden_authentication_policy)]
            if golden_version and golden_version.golden_authentication_policy
            else _authentication_policies(rows)
        )
        (path / "access-matrix.html").write_text(
            render_access_matrix(matrix, matrix_auth), encoding="utf-8"
        )
        reference_links.append({"label": "Access matrix", "href": "access-matrix.html"})
    (path / "campaign-report.html").write_text(
        render_html_report(
            campaign, rows, golden_version, reference_links, role_permissions, authentication_posture
        ), encoding="utf-8"
    )


def _role_permission_summary(csv_path: str | Path) -> dict[str, list[str]]:
    with Path(csv_path).open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    values: dict[str, set[str]] = {}
    for row in rows:
        values.setdefault(row["role"], set()).add(f"{row['resource']}: {row['permission']}")
    return {role: sorted(items) for role, items in sorted(values.items())}


def _authentication_policies(rows: list[dict[str, object]]) -> list[dict[str, str]]:
    providers = sorted({str(row.get("provider", "")) for row in rows if str(row.get("provider", ""))})
    if not providers:
        return [{"provider": "No provider", **_unknown_authentication_values()}]
    policies = []
    for provider in providers:
        provider_rows = [row for row in rows if str(row.get("provider", "")) == provider]
        source = {}
        for row in provider_rows:
            for key in ("authentication", "authentication_policy", "auth"):
                value = row.get(key)
                if isinstance(value, dict):
                    source.update(value)
            for key in (
                "authentication_method", "password_authentication", "password_policy",
                "mfa_requirement", "mfa_methods", "sso_federation", "token_authentication",
                "token_policy", "session_policy", "local_authentication", "authentication_status",
            ):
                if row.get(key) not in (None, ""):
                    source[key] = row[key]
        policies.append({"provider": provider, **_authentication_policy_values(source)})
    return policies


def _unknown_authentication_values() -> dict[str, str]:
    return {
        "authentication": "Not collected",
        "password": "Not collected",
        "password_policy": "Not collected",
        "mfa": "Not collected",
        "mfa_methods": "Not collected",
        "sso": "Not collected",
        "tokens": "Not collected",
        "token_policy": "Not collected",
        "session_policy": "Not collected",
        "local_authentication": "Not collected",
        "status": "Not collected",
    }


def _authentication_policy_values(source: dict[str, object]) -> dict[str, str]:
    unknown = _unknown_authentication_values()
    aliases = {
        "authentication": ("authentication", "authentication_method", "method"),
        "password": ("password", "password_authentication", "password_enabled"),
        "password_policy": ("password_policy",),
        "mfa": ("mfa", "mfa_requirement", "mfa_required"),
        "mfa_methods": ("mfa_methods", "methods"),
        "sso": ("sso", "sso_federation", "federation"),
        "tokens": ("tokens", "token_authentication", "token_enabled"),
        "token_policy": ("token_policy",),
        "session_policy": ("session_policy",),
        "local_authentication": ("local_authentication", "local_auth_allowed"),
        "status": ("status", "authentication_status"),
    }
    for output, keys in aliases.items():
        for key in keys:
            if key in source and source[key] not in (None, ""):
                unknown[output] = _safe_auth_value(source[key])
                break
    return unknown


def _safe_auth_value(value: object) -> str:
    if isinstance(value, bool):
        return "Enabled" if value else "Disabled"
    if isinstance(value, dict):
        allowed = {
            "minimum_length", "history", "lockout_threshold", "lockout_duration",
            "maximum_age", "expiration", "rotation", "ttl", "scopes", "owner",
            "required", "enabled", "forbidden", "managed_by",
        }
        values = [f"{key.replace('_', ' ').title()}: {value[key]}" for key in value if key in allowed and value[key] not in (None, "")]
        return "; ".join(values) or "Configured"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value) or "Not collected"
    return str(value)


def _authentication_posture_policy(posture: AuthenticationPosture) -> dict[str, str]:
    return {"provider": posture.provider, **_authentication_policy_values(posture.controls)}


def _authentication_report_html(
    observed: AuthenticationPosture | None,
    expected: AuthenticationPosture | None,
    fallback: list[dict[str, str]],
) -> str:
    if expected is None and observed is None:
        return _authentication_cards_html(fallback)
    source = observed or expected
    assert source is not None
    rows = compare_authentication_posture(expected, observed) if expected else []
    assessments = {row["control"]: row for row in rows}
    cards = [f'<div class="auth-provider"><strong>Provider</strong><span>{escape(source.provider)}</span></div>']
    for name, control in source.controls.items():
        nested = [key for key in control if key not in {"status", "expected", "observed", "value", "operator", "policies"}]
        fields = nested or [name]
        for field_name in fields:
            assessment_row = assessments.get(field_name) or assessments.get(name, {})
            expected_value = assessment_row.get("expected", "Not configured")
            if field_name == name:
                observed_value = assessment_row.get("observed", control.get("value", control.get("status", "Not collected")))
            else:
                observed_value = assessment_row.get("observed", control.get(field_name, control.get("status", "Not collected")))
            assessment = assessment_row.get("assessment", control.get("status", "not_collected"))
            title = name.replace("_", " ").title() if field_name == name else f"{name.replace('_', ' ').title()} — {field_name.replace('_', ' ').title()}"
            cards.append(
                f'<article class="auth-card"><h3>{escape(title)}</h3>'
                f'<dl class="auth-fields"><div class="auth-field"><dt>Expected</dt><dd>{escape(_safe_auth_value(expected_value))}</dd></div>'
                f'<div class="auth-field"><dt>Observed</dt><dd>{escape(_safe_auth_value(observed_value))}</dd></div>'
                f'<div class="auth-field"><dt>Assessment</dt><dd>{escape(str(assessment).title())}</dd></div></dl></article>'
            )
    return f'<div class="authentication-cards">{"".join(cards)}</div>'


def _authentication_cards_html(policies: list[dict[str, str]]) -> str:
    cards = []
    fields = [
        ("authentication", "Authentication"), ("password", "Password"),
        ("password_policy", "Password policy"), ("mfa", "MFA"),
        ("mfa_methods", "MFA methods"), ("sso", "SSO / federation"),
        ("tokens", "Tokens"), ("token_policy", "Token policy"),
        ("session_policy", "Session policy"),
        ("local_authentication", "Local authentication"), ("status", "Status"),
    ]
    for policy in policies:
        rows_html = "".join(
            f'<div class="auth-field"><dt>{escape(label)}</dt><dd>{escape(policy.get(key) or "Not collected")}</dd></div>'
            for key, label in fields
        )
        cards.append(f'<article class="auth-card"><h3>{escape(policy["provider"])}</h3><dl class="auth-fields">{rows_html}</dl></article>')
    return f'<div class="authentication-cards">{"".join(cards)}</div>'


def render_access_matrix(csv_path: str | Path, authentication_policies: list[dict[str, str]] | None = None) -> str:
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
    html = f"""<!doctype html>
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
h2 {{ margin-top:0; font-size:28px; }}
p {{ color:var(--muted); }}
.auth-section {{ margin:64px 0 88px; }}
.authentication-cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:24px; }}
.auth-card {{ background:white; border:1px solid var(--line); border-radius:8px; padding:28px; box-shadow:0 14px 35px rgba(15,23,42,.06); }}
.auth-card h3 {{ margin:0 0 24px; font-size:22px; }}
.auth-fields {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:18px 24px; }}
.auth-field dt {{ color:var(--muted); font-size:12px; font-weight:800; text-transform:uppercase; }}
.auth-field dd {{ margin:5px 0 0; font-weight:800; overflow-wrap:anywhere; }}
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
<body><main><h1>Golden Source</h1><p>Authentication policy and role-to-resource permissions used as the reference for access reviews.</p><section class="auth-section"><h2>01 — Authentication Policy</h2><p>Expected authentication controls. Unknown values are shown explicitly when the source did not collect them.</p>__AUTHENTICATION_CARDS__</section><section class="matrix"><h2>02 — Golden Access Matrix</h2><table><thead><tr><th>Resource</th>{head}</tr></thead><tbody>{body}</tbody></table></section></main></body></html>"""
    html = html.replace("__AUTHENTICATION_CARDS__", _authentication_cards_html(authentication_policies or [{"provider": "No provider", **_unknown_authentication_values()}]))
    return html


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
    authentication_posture: AuthenticationPosture | None = None,
) -> str:
    summary = _summary(rows)
    campaign_name = campaign.display_name or campaign.name
    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    providers = sorted({str(row["provider"]) for row in rows if str(row["provider"])})
    services = sorted({str(row["service"]) for row in rows if str(row["service"])})
    findings = sorted(
        {
            finding.strip()
            for row in rows
            for finding in str(row.get("findings", "")).split(",")
            if finding.strip()
        }
    )
    options = {
        "service": services,
        "classification": sorted({str(row["classification"]) for row in rows}),
        "decision": sorted({str(row["decision"]) for row in rows}),
        "finding": findings,
        "status": sorted({str(row["identity_status"]) for row in rows}),
        "reviewer": sorted({str(row["reviewer"]) for row in rows}),
    }
    filters = "".join(_filter_select_html(name, values) for name, values in options.items())
    references = _reference_links_html(reference_links or [])
    authentication_html = _authentication_report_html(
        authentication_posture,
        golden_version.golden_authentication_policy if golden_version else None,
        _authentication_policies(rows),
    )
    report_rows = _html_safe_rows(rows)
    data_json = (
        json.dumps(report_rows)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("</", "<\\/")
    )
    labels_json = json.dumps(_report_labels()).replace("</", "<\\/")
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Review Report - __CAMPAIGN_TITLE__</title>
<style>
:root {
  --bg:#f8fafc;
  --surface:#ffffff;
  --surface-soft:#f1f5f9;
  --ink:#0f172a;
  --muted:#64748b;
  --line:#dbe3ef;
  --line-strong:#cbd5e1;
  --blue:#1d4ed8;
  --blue-action:#2563eb;
  --blue-soft:#dbeafe;
  --green:#16a34a;
  --green-soft:#dcfce7;
  --orange:#f59e0b;
  --orange-soft:#fef3c7;
  --red:#dc2626;
  --red-soft:#fee2e2;
  --gray-soft:#e2e8f0;
  --shadow:0 18px 45px rgba(15,23,42,.08);
}
* { box-sizing:border-box; }
html { background:var(--bg); }
body {
  margin:0;
  background:var(--bg);
  color:var(--ink);
  font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  line-height:1.5;
}
main { max-width:1480px; margin:0 auto; padding:0 40px 96px; }
.report-hero {
  background:linear-gradient(135deg,#0f172a 0%,#17346f 58%,#1d4ed8 100%);
  color:white;
  padding:72px 0 76px;
  margin-bottom:88px;
}
.hero-inner { max-width:1480px; margin:0 auto; padding:0 40px; }
.eyebrow { margin:0 0 18px; color:#bfdbfe; font-size:13px; font-weight:800; text-transform:uppercase; letter-spacing:.08em; }
h1 { margin:0; font-size:40px; line-height:1.08; letter-spacing:0; }
.hero-subtitle { max-width:760px; margin:24px 0 0; color:#dbeafe; font-size:18px; }
.hero-meta { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:24px; margin-top:48px; }
.meta-item { border:1px solid rgba(219,234,254,.24); background:rgba(255,255,255,.08); border-radius:8px; padding:22px 24px; min-height:96px; }
.meta-label { display:block; color:#bfdbfe; font-size:12px; font-weight:800; text-transform:uppercase; }
.meta-value { display:block; margin-top:10px; font-size:17px; font-weight:800; overflow-wrap:anywhere; }
.references { margin-top:28px; display:flex; gap:14px; flex-wrap:wrap; }
.references a { color:white; border:1px solid rgba(255,255,255,.32); border-radius:999px; padding:8px 13px; text-decoration:none; font-weight:800; }
.report-section { margin-top:88px; }
.section-heading { margin-bottom:38px; max-width:780px; }
.section-number { color:var(--blue); font-size:15px; font-weight:900; letter-spacing:.12em; }
.section-kicker { margin-top:10px; color:var(--muted); font-size:13px; font-weight:900; letter-spacing:.1em; text-transform:uppercase; }
h2 { margin:8px 0 0; font-size:32px; line-height:1.15; letter-spacing:0; }
.section-copy { margin:16px 0 0; color:var(--muted); font-size:17px; }
.kpi-groups { display:flex; flex-direction:column; gap:32px; }
.authentication-cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:28px; }
.auth-card { background:var(--surface); border:1px solid var(--line); border-radius:8px; box-shadow:var(--shadow); padding:30px; }
.auth-card h3 { margin:0 0 26px; font-size:22px; }
.auth-fields { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:22px 28px; }
.auth-field dt { color:var(--muted); font-size:12px; font-weight:900; text-transform:uppercase; }
.auth-field dd { margin:6px 0 0; font-size:15px; font-weight:800; overflow-wrap:anywhere; }
.kpi-group { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:28px; }
.kpi-card, .chart-card, .finding-card, .service-card, .filter-panel {
  background:var(--surface);
  border:1px solid var(--line);
  border-radius:8px;
  box-shadow:var(--shadow);
}
.kpi-card { padding:28px; min-height:148px; display:flex; flex-direction:column; justify-content:space-between; }
.kpi-top { display:flex; align-items:center; justify-content:space-between; gap:18px; }
.kpi-label { color:var(--muted); font-size:13px; font-weight:900; text-transform:uppercase; }
.kpi-icon { width:36px; height:36px; border-radius:8px; background:var(--blue-soft); color:var(--blue); display:grid; place-items:center; font-weight:900; }
.kpi-value { margin-top:20px; font-size:36px; line-height:1; font-weight:900; }
.kpi-note { margin-top:12px; color:var(--muted); font-size:14px; }
.charts-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:28px; align-items:stretch; }
.chart-card { padding:30px; min-height:430px; display:flex; flex-direction:column; }
.chart-title { margin:0; font-size:20px; font-weight:900; }
.chart-copy { margin:8px 0 26px; color:var(--muted); }
.chart-stage { flex:1; min-height:280px; display:grid; place-items:center; }
.legend { display:flex; flex-wrap:wrap; gap:12px 18px; margin-top:26px; }
.legend-item { display:flex; align-items:center; gap:8px; color:var(--muted); font-size:14px; }
.swatch { width:12px; height:12px; border-radius:3px; }
.bar-chart { width:100%; display:flex; flex-direction:column; gap:20px; }
.bar-row { display:grid; grid-template-columns:150px 1fr 52px; gap:16px; align-items:center; font-size:14px; }
.bar-track { height:18px; border-radius:999px; background:var(--surface-soft); overflow:hidden; }
.bar-fill { height:100%; border-radius:999px; min-width:2px; }
.empty-state { color:var(--muted); font-weight:700; text-align:center; }
.findings-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:28px; }
.finding-card { padding:28px; min-height:150px; }
.finding-count { font-size:34px; line-height:1; font-weight:900; }
.finding-label { margin-top:20px; font-weight:900; }
.finding-copy { margin-top:8px; color:var(--muted); font-size:14px; }
.finding-card.warning { border-color:#fed7aa; }
.finding-card.danger { border-color:#fecaca; }
.filter-panel { padding:30px; margin-bottom:36px; }
.search-row { display:grid; grid-template-columns:1fr auto auto; gap:18px; align-items:end; margin-bottom:28px; }
.field { display:flex; flex-direction:column; gap:10px; color:var(--muted); font-size:13px; font-weight:900; text-transform:uppercase; }
input, select {
  width:100%; min-height:46px; border:1px solid var(--line-strong); border-radius:8px; background:white; color:var(--ink); padding:0 14px; font:inherit; font-size:15px;
}
.filter-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:24px; }
.button { min-height:46px; border:1px solid var(--line-strong); border-radius:8px; padding:0 16px; background:white; color:var(--ink); font-weight:900; cursor:pointer; }
.button.primary { border-color:var(--blue-action); background:var(--blue-action); color:white; }
.toggle { display:flex; align-items:center; gap:10px; min-height:46px; padding:0 16px; border:1px solid var(--line-strong); border-radius:8px; background:white; color:var(--ink); font-weight:900; text-transform:none; }
.toggle input { width:18px; min-height:18px; }
.services { display:flex; flex-direction:column; gap:28px; }
.service-card { overflow:hidden; }
.service-toggle { width:100%; border:0; background:white; color:var(--ink); padding:28px 30px; display:grid; grid-template-columns:1fr auto; gap:24px; text-align:left; cursor:pointer; }
.service-title { font-size:22px; font-weight:900; }
.service-meta { margin-top:14px; display:flex; flex-wrap:wrap; gap:14px 24px; color:var(--muted); font-size:15px; }
.service-counts { display:flex; flex-wrap:wrap; justify-content:flex-end; gap:12px; min-width:320px; }
.pill { display:inline-flex; align-items:center; min-height:30px; border-radius:999px; padding:0 11px; background:var(--surface-soft); color:var(--muted); font-size:13px; font-weight:900; }
.pill.good { background:var(--green-soft); color:#166534; }
.pill.warn { background:var(--orange-soft); color:#92400e; }
.pill.bad { background:var(--red-soft); color:#991b1b; }
.service-detail { border-top:1px solid var(--line); padding:0 30px 32px; }
.table-wrap { overflow:auto; padding-top:24px; }
table { width:100%; min-width:1080px; border-collapse:separate; border-spacing:0; font-size:15px; }
th { position:sticky; top:0; z-index:1; background:#f8fafc; color:var(--muted); font-size:12px; font-weight:900; text-transform:uppercase; text-align:left; padding:16px; border-bottom:1px solid var(--line-strong); cursor:pointer; }
td { padding:18px 16px; min-height:52px; border-bottom:1px solid var(--line); vertical-align:middle; }
tbody tr:hover { background:#f8fbff; }
.badge { display:inline-flex; align-items:center; min-height:28px; border-radius:999px; padding:0 10px; background:var(--surface-soft); color:var(--muted); font-size:13px; font-weight:900; white-space:nowrap; }
.badge.expected_and_observed, .badge.approve, .badge.yes, .badge.active { background:var(--green-soft); color:#166534; }
.badge.unexpected, .badge.revoke, .badge.disabled { background:var(--red-soft); color:#991b1b; }
.badge.missing, .badge.pending, .badge.unknown_due_to_scope { background:var(--orange-soft); color:#92400e; }
.badge.not_applicable, .badge.no { background:var(--gray-soft); color:#475569; }
.finding-list { display:flex; flex-wrap:wrap; gap:8px; }
.finding-text { color:var(--red); font-weight:800; }
.no-findings { color:var(--muted); font-weight:800; }
.results-summary { margin:0 0 22px; color:var(--muted); font-weight:800; }
@media (max-width:1180px) {
  .hero-meta, .kpi-group, .charts-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .filter-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
}
@media (max-width:760px) {
  main, .hero-inner { padding-left:22px; padding-right:22px; }
  .report-hero { padding:48px 0 56px; margin-bottom:72px; }
  h1 { font-size:34px; }
  h2 { font-size:28px; }
  .report-section { margin-top:76px; }
  .hero-meta, .kpi-group, .charts-grid, .filter-grid, .search-row { grid-template-columns:1fr; }
  .service-toggle { grid-template-columns:1fr; }
  .service-counts { min-width:0; justify-content:flex-start; }
}
@media print {
  body { background:white; }
  main { padding:0 24px 40px; }
  .report-hero { color:var(--ink); background:white; padding:28px 0 36px; margin-bottom:48px; border-bottom:1px solid var(--line); }
  .eyebrow, .hero-subtitle, .meta-label, .meta-value { color:var(--ink); }
  .meta-item, .kpi-card, .chart-card, .finding-card, .service-card { box-shadow:none; break-inside:avoid; }
  .filter-panel, .references { display:none; }
  .service-detail { display:block !important; }
  .report-section { margin-top:56px; break-inside:avoid; }
  th { position:static; }
}
</style>
</head>
<body>
<header class="report-hero">
  <div class="hero-inner">
    <p class="eyebrow">Access Review Report</p>
    <h1>__CAMPAIGN_TITLE__</h1>
    <p class="hero-subtitle">Analyse des habilitations et comparaison avec la Golden Source.</p>
    <div class="hero-meta">
      <div class="meta-item"><span class="meta-label">Organisation / Provider</span><span class="meta-value">__PROVIDERS__</span></div>
      <div class="meta-item"><span class="meta-label">Golden Source</span><span class="meta-value">__GOLDEN__</span></div>
      <div class="meta-item"><span class="meta-label">Generated on</span><span class="meta-value">__GENERATED__</span></div>
      <div class="meta-item"><span class="meta-label">Status</span><span class="meta-value">__STATUS__</span></div>
    </div>
    __REFERENCES__
  </div>
</header>
<main>
  <section class="report-section" aria-labelledby="overview-title">
    <div class="section-heading">
      <div class="section-number">01</div>
      <div class="section-kicker">Synthèse</div>
      <h2 id="overview-title">Vue d’ensemble</h2>
      <p class="section-copy">Indicateurs clés de la campagne d’Access Review.</p>
    </div>
    __SUMMARY__
  </section>

  <section class="report-section" aria-labelledby="authentication-title">
    <div class="section-heading">
      <div class="section-number">02</div>
      <div class="section-kicker">Golden Source</div>
      <h2 id="authentication-title">Authentication Posture</h2>
      <p class="section-copy">Expected authentication controls used as the reference for access reviews.</p>
    </div>
    __AUTHENTICATION__
  </section>

  <section class="report-section" aria-labelledby="charts-title">
    <div class="section-heading">
      <div class="section-number">02</div>
      <div class="section-kicker">Analyses</div>
      <h2 id="charts-title">Visualisations</h2>
      <p class="section-copy">Répartition des accès et décisions.</p>
    </div>
    <div class="charts-grid">
      <article class="chart-card"><h3 class="chart-title">Access Review Outcome</h3><p class="chart-copy">Expected, unexpected, missing et scope incomplet.</p><div class="chart-stage" id="outcome-chart"></div><div class="legend" id="outcome-legend"></div></article>
      <article class="chart-card"><h3 class="chart-title">Review Decisions</h3><p class="chart-copy">Décisions de revue actuellement enregistrées.</p><div class="chart-stage" id="decision-chart"></div></article>
      <article class="chart-card"><h3 class="chart-title">Accesses by service / role</h3><p class="chart-copy">Services et rôles les plus représentés.</p><div class="chart-stage" id="service-chart"></div></article>
    </div>
  </section>

  <section class="report-section" aria-labelledby="findings-title">
    <div class="section-heading">
      <div class="section-number">03</div>
      <div class="section-kicker">Points d’attention</div>
      <h2 id="findings-title">Findings</h2>
      <p class="section-copy">Anomalies et points nécessitant une attention.</p>
    </div>
    <div class="findings-grid" id="findings-grid"></div>
  </section>

  <section class="report-section" aria-labelledby="details-title">
    <div class="section-heading">
      <div class="section-number">04</div>
      <div class="section-kicker">Résultats détaillés</div>
      <h2 id="details-title">Par service / accès</h2>
      <p class="section-copy">Détail des identités et de leurs droits.</p>
    </div>
    <section class="filter-panel" aria-label="Report filters">
      <div class="search-row">
        <label class="field">Search<input id="filter-search" type="search" placeholder="Search identity, service, reviewer, finding..."></label>
        <label class="toggle"><input id="filter-anomalies" type="checkbox">Only anomalies</label>
        <button class="button" type="button" id="reset-filters">Reset filters</button>
      </div>
      <div class="filter-grid">__FILTERS__</div>
    </section>
    <p class="results-summary" id="results-summary"></p>
    <section class="services" id="grouped"></section>
  </section>
</main>
<script>
const rows = __DATA__;
const labels = __LABELS__;
const filterNames = ["service","classification","decision","finding","status","reviewer"];
const sortFields = ["identity","identity_status","expected","observed","classification","findings","decision","reviewer"];
let sortState = { key: "identity", direction: "asc" };
const chartColors = ["#16a34a", "#dc2626", "#f59e0b", "#64748b", "#1d4ed8", "#0f766e"];

function value(row, key) { return row[key] ?? ""; }
function label(key) { return labels[key] || key.replaceAll("_", " "); }
function hasFinding(row) { return value(row, "findings").trim() !== ""; }
function isAnomaly(row) { return row.classification !== "expected_and_observed" || hasFinding(row); }
function normalizedFindings(row) { return value(row, "findings").split(",").map(item => item.trim()).filter(Boolean); }
function filterValue(name) { const el = document.getElementById("filter-" + name); return el ? el.value.toLowerCase() : ""; }
function textEl(tag, text, className) { const el = document.createElement(tag); el.textContent = text ?? "-"; if (el.textContent === "") el.textContent = "-"; if (className) el.className = className; return el; }
function badge(text, kind) { const span = document.createElement("span"); span.className = "badge " + (kind || String(text)); span.textContent = text; return span; }

function matches(row) {
  const search = filterValue("search");
  if (search) {
    const haystack = [row.identity, row.service, row.access, row.provider, row.reviewer, row.findings, row.issue, row.comment].map(item => value({ item }, "item").toLowerCase()).join(" ");
    if (!haystack.includes(search)) return false;
  }
  for (const name of filterNames) {
    const selected = filterValue(name);
    if (!selected) continue;
    if (name === "finding") {
      if (!value(row, "findings").toLowerCase().includes(selected) && !value(row, "issue").toLowerCase().includes(selected)) return false;
    } else if (name === "status") {
      if (value(row, "identity_status").toLowerCase() !== selected) return false;
    } else if (value(row, name).toLowerCase() !== selected) {
      return false;
    }
  }
  const anomalies = document.getElementById("filter-anomalies").checked;
  return !anomalies || isAnomaly(row);
}

function compareRows(a, b) {
  const av = value(a, sortState.key).toLowerCase();
  const bv = value(b, sortState.key).toLowerCase();
  const result = av.localeCompare(bv, "en", { numeric: true, sensitivity: "base" });
  return sortState.direction === "asc" ? result : -result;
}

function groupedRows(items) {
  const groups = new Map();
  for (const row of items) {
    const key = value(row, "service") + "||" + value(row, "access");
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }
  return Array.from(groups.values()).sort((a, b) => (value(a[0], "service") + value(a[0], "access")).localeCompare(value(b[0], "service") + value(b[0], "access")));
}

function renderFindingsCell(td, row) {
  const items = normalizedFindings(row);
  const fallback = value(row, "issue") || (value(row, "classification") !== "expected_and_observed" ? label(value(row, "classification")) : "");
  if (!items.length && !fallback) { td.appendChild(textEl("span", "No findings", "no-findings")); return; }
  const list = document.createElement("div");
  list.className = "finding-list";
  for (const item of items) list.appendChild(badge(label(item), "warn"));
  if (!items.length && fallback) list.appendChild(textEl("span", fallback, "finding-text"));
  td.appendChild(list);
}

function renderTable(container, items) {
  const wrap = document.createElement("div");
  wrap.className = "table-wrap";
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const trh = document.createElement("tr");
  const columns = [
    ["identity", "Identity"], ["identity_status", "Status"], ["expected", "Expected"], ["observed", "Observed"],
    ["classification", "Classification"], ["findings", "Findings"], ["decision", "Decision"], ["reviewer", "Reviewer"], ["comment", "Comment"]
  ];
  for (const [key, title] of columns) {
    const th = textEl("th", title + (sortState.key === key ? (sortState.direction === "asc" ? " ↑" : " ↓") : ""));
    if (sortFields.includes(key)) th.addEventListener("click", () => { sortState = { key, direction: sortState.key === key && sortState.direction === "asc" ? "desc" : "asc" }; renderDetails(); });
    trh.appendChild(th);
  }
  thead.appendChild(trh);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const row of items.slice().sort(compareRows)) {
    const tr = document.createElement("tr");
    tr.dataset.classification = value(row, "classification");
    tr.appendChild(textEl("td", value(row, "identity")));
    const status = document.createElement("td"); status.appendChild(badge(label(value(row, "identity_status")), value(row, "identity_status"))); tr.appendChild(status);
    const expected = document.createElement("td"); expected.appendChild(badge(label(value(row, "expected")), value(row, "expected"))); tr.appendChild(expected);
    const observed = document.createElement("td"); observed.appendChild(badge(label(value(row, "observed")), value(row, "observed"))); tr.appendChild(observed);
    const classification = document.createElement("td"); classification.appendChild(badge(label(value(row, "classification")), value(row, "classification"))); tr.appendChild(classification);
    const findingsTd = document.createElement("td"); renderFindingsCell(findingsTd, row); tr.appendChild(findingsTd);
    const decision = document.createElement("td"); decision.appendChild(badge(label(value(row, "decision")), value(row, "decision"))); tr.appendChild(decision);
    tr.appendChild(textEl("td", value(row, "reviewer")));
    tr.appendChild(textEl("td", value(row, "comment")));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  container.appendChild(wrap);
}

function renderDetails() {
  const out = document.getElementById("grouped");
  out.replaceChildren();
  const visible = rows.filter(matches);
  document.getElementById("results-summary").textContent = visible.length + " result" + (visible.length === 1 ? "" : "s") + " displayed";
  if (!visible.length) { out.appendChild(textEl("p", "No matching rows.", "empty-state")); return; }
  for (const group of groupedRows(visible)) {
    const first = group[0];
    const article = document.createElement("article");
    article.className = "service-card";
    const button = document.createElement("button");
    button.className = "service-toggle";
    button.type = "button";
    const titleWrap = document.createElement("div");
    titleWrap.appendChild(textEl("div", value(first, "service") || "No service", "service-title"));
    const meta = textEl("div", "Owner: " + (value(first, "owner") || "unassigned") + " · Access: " + (value(first, "access") || "none"), "service-meta");
    titleWrap.appendChild(meta);
    const counts = document.createElement("div"); counts.className = "service-counts";
    const identities = new Set(group.map(row => value(row, "identity"))).size;
    const observed = group.filter(row => row.observed === "yes").length;
    const expected = group.filter(row => row.expected === "yes").length;
    const findingCount = group.filter(isAnomaly).length;
    counts.appendChild(textEl("span", identities + " identities", "pill"));
    counts.appendChild(textEl("span", observed + " observed", "pill"));
    counts.appendChild(textEl("span", expected + " expected", "pill"));
    counts.appendChild(textEl("span", findingCount + " finding" + (findingCount === 1 ? "" : "s"), findingCount ? "pill bad" : "pill good"));
    button.appendChild(titleWrap); button.appendChild(counts); article.appendChild(button);
    const detail = document.createElement("div"); detail.className = "service-detail";
    renderTable(detail, group);
    const open = group.some(isAnomaly);
    detail.hidden = !open;
    button.setAttribute("aria-expanded", open ? "true" : "false");
    button.addEventListener("click", () => { detail.hidden = !detail.hidden; button.setAttribute("aria-expanded", detail.hidden ? "false" : "true"); });
    article.appendChild(detail);
    out.appendChild(article);
  }
}

function countBy(key) {
  const values = new Map();
  for (const row of rows) values.set(value(row, key), (values.get(value(row, key)) || 0) + 1);
  return values;
}
function countFinding(name) { return rows.filter(row => value(row, "findings").includes(name) || row.classification === name).length; }
function svgEl(tag, attrs) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, val] of Object.entries(attrs)) el.setAttribute(key, val);
  return el;
}
function donutChart(target, legendTarget, entries) {
  const total = entries.reduce((sum, item) => sum + item.value, 0);
  if (!total) { target.appendChild(textEl("p", "No data", "empty-state")); return; }
  const svg = svgEl("svg", { viewBox: "0 0 42 42", width: "260", height: "260", role: "img", "aria-label": "Access review outcome" });
  svg.appendChild(svgEl("circle", { r: "15.915", cx: "20", cy: "20", fill: "transparent", stroke: "#e2e8f0", "stroke-width": "6" }));
  let offset = 0;
  for (const [index, item] of entries.entries()) {
    const pct = item.value / total;
    svg.appendChild(svgEl("circle", { r: "15.915", cx: "20", cy: "20", fill: "transparent", stroke: chartColors[index], "stroke-width": "6", "stroke-dasharray": (pct * 100) + " " + (100 - pct * 100), "stroke-dashoffset": String(-offset) }));
    offset += pct * 100;
  }
  const totalText = svgEl("text", { x: "21", y: "19", "text-anchor": "middle", "font-size": "5", "font-weight": "800", fill: "#0f172a" });
  totalText.textContent = String(total);
  svg.appendChild(totalText);
  const caption = svgEl("text", { x: "21", y: "24", "text-anchor": "middle", "font-size": "3", fill: "#64748b" });
  caption.textContent = "total";
  svg.appendChild(caption);
  target.appendChild(svg);
  for (const [index, item] of entries.entries()) {
    const pct = Math.round((item.value / total) * 100);
    const el = document.createElement("div");
    el.className = "legend-item";
    const swatch = document.createElement("span");
    swatch.className = "swatch";
    swatch.style.background = chartColors[index];
    el.appendChild(swatch);
    el.appendChild(textEl("span", item.label + ": " + item.value + " (" + pct + "%)"));
    legendTarget.appendChild(el);
  }
}
function barChart(target, entries, horizontalLabel) {
  const max = Math.max(1, ...entries.map(item => item.value));
  const box = document.createElement("div"); box.className = "bar-chart";
  for (const [index, item] of entries.entries()) {
    const row = document.createElement("div"); row.className = "bar-row";
    row.appendChild(textEl("span", item.label));
    const track = document.createElement("div"); track.className = "bar-track";
    const fill = document.createElement("div"); fill.className = "bar-fill"; fill.style.width = Math.round((item.value / max) * 100) + "%"; fill.style.background = chartColors[index % chartColors.length]; track.appendChild(fill);
    row.appendChild(track); row.appendChild(textEl("strong", item.value)); box.appendChild(row);
  }
  if (!entries.length) box.appendChild(textEl("p", horizontalLabel || "No data", "empty-state"));
  target.appendChild(box);
}
function renderCharts() {
  donutChart(document.getElementById("outcome-chart"), document.getElementById("outcome-legend"), [
    { label: label("expected_and_observed"), value: countFinding("expected_and_observed") },
    { label: label("unexpected"), value: countFinding("unexpected") },
    { label: label("missing"), value: countFinding("missing") },
    { label: label("unknown_due_to_scope"), value: countFinding("unknown_due_to_scope") }
  ]);
  const decisions = countBy("decision");
  barChart(document.getElementById("decision-chart"), ["approve","revoke","not_applicable","pending"].map(key => ({ label: label(key), value: decisions.get(key) || 0 })));
  const services = Array.from(countBy("service").entries()).map(([name, value]) => ({ label: name || "No service", value })).sort((a, b) => b.value - a.value).slice(0, 8);
  barChart(document.getElementById("service-chart"), services, "No service data");
}
function renderFindingCards() {
  const grid = document.getElementById("findings-grid");
  const entries = ["unexpected","missing","disabled_with_access","technical_account_without_owner","shared_account_without_owner","unknown_due_to_scope"];
  for (const key of entries) {
    const card = document.createElement("article"); card.className = "finding-card " + (key === "unexpected" || key.includes("disabled") ? "danger" : "warning");
    card.appendChild(textEl("div", countFinding(key), "finding-count"));
    card.appendChild(textEl("div", label(key), "finding-label"));
    card.appendChild(textEl("div", key === "unexpected" || key === "missing" ? "Access review gap" : "Account governance signal", "finding-copy"));
    grid.appendChild(card);
  }
}
function resetFilters() {
  document.getElementById("filter-search").value = "";
  document.getElementById("filter-anomalies").checked = false;
  for (const name of filterNames) document.getElementById("filter-" + name).value = "";
  renderDetails();
}
for (const name of ["search", ...filterNames]) document.getElementById("filter-" + name).addEventListener("input", renderDetails);
document.getElementById("filter-anomalies").addEventListener("change", renderDetails);
document.getElementById("reset-filters").addEventListener("click", resetFilters);
renderCharts();
renderFindingCards();
renderDetails();
</script>
</body>
</html>"""
    replacements = {
        "__CAMPAIGN_TITLE__": escape(campaign_name),
        "__PROVIDERS__": escape(", ".join(providers) if providers else "No provider"),
        "__GOLDEN__": escape(f"Golden Source v{golden_version.version}" if golden_version else "none"),
        "__GENERATED__": escape(generated_at),
        "__STATUS__": escape(str(campaign.status)),
        "__REFERENCES__": references,
        "__SUMMARY__": _summary_html(summary),
        "__AUTHENTICATION__": authentication_html,
        "__FILTERS__": filters,
        "__DATA__": data_json,
        "__LABELS__": labels_json,
    }
    for placeholder, value in replacements.items():
        html = html.replace(placeholder, value)
    return html


def _filter_select_html(name: str, values: list[str]) -> str:
    label = _report_labels().get(name, name.replace("_", " ").title())
    options = "".join(f'<option value="{escape(value)}">{escape(_report_labels().get(value, value) or "Unassigned")}</option>' for value in values)
    return f'<label class="field">{escape(label)}<select id="filter-{escape(name)}"><option value="">All</option>{options}</select></label>'


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
    groups = [
        ("Scope", ["providers", "identities", "observed", "expected"]),
        ("Access review status", ["expected_and_observed", "unexpected", "missing", "unknown_due_to_scope"]),
        ("Decisions", ["approve", "revoke", "not_applicable", "pending"]),
    ]
    rendered_groups = []
    for title, keys in groups:
        cards = "".join(_kpi_card_html(key, summary.get(key, 0)) for key in keys)
        rendered_groups.append(f'<section class="kpi-block" aria-label="{escape(title)}"><div class="kpi-group">{cards}</div></section>')
    return f'<div class="kpi-groups">{"".join(rendered_groups)}</div>'


def _kpi_card_html(key: str, value: int) -> str:
    labels = _report_labels()
    icon = labels.get(f"{key}_icon", "#")
    note = labels.get(f"{key}_note", "")
    return (
        '<article class="kpi-card">'
        f'<div class="kpi-top"><div class="kpi-label">{escape(labels.get(key, key))}</div><div class="kpi-icon">{escape(icon)}</div></div>'
        f'<div class="kpi-value">{value}</div>'
        f'<div class="kpi-note">{escape(note)}</div>'
        '</article>'
    )


def _html_safe_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    authentication_payload_keys = {"authentication", "authentication_policy", "auth"}
    return [
        {
            key: ("" if value is None else value)
            for key, value in row.items()
            if key not in authentication_payload_keys
        }
        for row in rows
    ]


def _report_labels() -> dict[str, str]:
    return {
        "service": "Service",
        "classification": "Classification",
        "decision": "Decision",
        "finding": "Finding",
        "status": "Status",
        "reviewer": "Reviewer",
        "providers": "Providers",
        "identities": "Identities",
        "observed": "Observed",
        "expected": "Expected",
        "expected_and_observed": "Expected & observed",
        "unexpected": "Unexpected",
        "missing": "Missing",
        "unknown_due_to_scope": "Unknown due to scope",
        "disabled_with_access": "Disabled user with access",
        "technical_account_without_owner": "Technical account without owner",
        "shared_account_without_owner": "Shared account without owner",
        "collection_incomplete": "Incomplete collection",
        "invalid_owner": "Invalid owner",
        "unknown_identity": "Unknown identity",
        "unknown_provider": "Unknown provider",
        "orphaned_access": "Orphaned access",
        "deleted_account_with_access": "Deleted account with access",
        "decision_on_missing_object": "Decision on missing object",
        "approve": "Approve",
        "revoke": "Revoke",
        "not_applicable": "Not applicable",
        "pending": "Pending",
        "yes": "Yes",
        "no": "No",
        "active": "Active",
        "disabled": "Disabled",
        "deleted": "Deleted",
        "unknown": "Unknown",
        "providers_icon": "P",
        "identities_icon": "I",
        "observed_icon": "O",
        "expected_icon": "E",
        "expected_and_observed_icon": "OK",
        "unexpected_icon": "!",
        "missing_icon": "M",
        "unknown_due_to_scope_icon": "?",
        "approve_icon": "A",
        "revoke_icon": "R",
        "not_applicable_icon": "NA",
        "pending_icon": "P",
        "providers_note": "Source systems represented",
        "identities_note": "Distinct identities reviewed",
        "observed_note": "Accesses seen in collectors",
        "expected_note": "Accesses expected by policy",
        "expected_and_observed_note": "Aligned with Golden Source",
        "unexpected_note": "Observed but not expected",
        "missing_note": "Expected but not observed",
        "unknown_due_to_scope_note": "Incomplete collection scope",
        "approve_note": "Approved decisions",
        "revoke_note": "Revocation decisions",
        "not_applicable_note": "Marked not applicable",
        "pending_note": "Awaiting reviewer action",
    }


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
