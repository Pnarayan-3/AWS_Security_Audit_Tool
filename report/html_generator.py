from html import escape
from pathlib import Path


def generate_html(findings, output_path="reports/security-report.html"):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    rows = []

    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{escape(f.rule_id)}</td>"
            f"<td>{escape(f.severity)}</td>"
            f"<td>{escape(f.title)}</td>"
            f"<td>{escape(f.service)}</td>"
            f"<td>{escape(f.resource_id)}</td>"
            f"<td>{escape(f.description)}</td>"
            f"<td>{escape(f.remediation)}</td>"
            "</tr>"
        )

    html = f"""<!doctype html>
<html lang="en">

<head>
<meta charset="utf-8">

<title>AWS Security Audit Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 30px;
}}

table {{
    border-collapse: collapse;
    width: 100%;
}}

th, td {{
    border: 1px solid #ccc;
    padding: 8px;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #eee;
}}

</style>

</head>

<body>

<h1>AWS Security Audit Report</h1>

<p>
    Total findings:
    <strong>{len(findings)}</strong>
</p>

<table>

<thead>

<tr>
    <th>Rule</th>
    <th>Severity</th>
    <th>Title</th>
    <th>Service</th>
    <th>Resource</th>
    <th>Description</th>
    <th>Remediation</th>
</tr>

</thead>

<tbody>

{''.join(rows) if rows else '<tr><td colspan="7">No findings.</td></tr>'}

</tbody>

</table>

</body>

</html>
"""

    path.write_text(
        html,
        encoding="utf-8"
    )

    return path