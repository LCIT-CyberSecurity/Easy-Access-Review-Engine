# Reports

The campaign report is a standalone, offline HTML report. It presents the review progressively:

- Overview and KPI groups;
- explicit findings with level, risk, affected objects and recommendation;
- Golden Source / access matrix grouped by role and searchable by role, service, component, permission, identity and owner;
- expected versus observed campaign delta;
- decisions and detailed access results.

Exports written by `campaign-export` or `write_reports` are UTF-8 with BOM for spreadsheet compatibility:

- `campaign-report.html`
- `campaign-results.json` and `campaign-results.csv`
- `campaign-findings.csv`
- `golden-source.csv`
- `campaign-delta.csv`
- `campaign-decisions.csv`
- `access-matrix.html` when a policy matrix is available

The HTML PDF action delegates to the browser print dialog, while print CSS removes interactive controls and expands collapsed details for pagination.
