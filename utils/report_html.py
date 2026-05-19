"""
Ne0 - Interactive HTML Report Generator
Produces a self-contained HTML report with:
  - Risk score dashboard
  - Chart.js charts (severity breakdown, modules)
  - Filterable findings table
  - Collapsible sections per module
"""

import json
import datetime
from pathlib import Path


def _severity_color(sev: str) -> str:
    return {
        "CRITICAL": "#ef4444",
        "HIGH":     "#f97316",
        "MEDIUM":   "#facc15",
        "LOW":      "#22c55e",
        "INFO":     "#60a5fa",
        "PASS":     "#22c55e",
        "FAIL":     "#ef4444",
        "WARN":     "#facc15",
        "SAFE":     "#22c55e",
    }.get(sev.upper(), "#94a3b8")


def _badge(text: str, color: str) -> str:
    return f'<span style="background:{color};color:#000;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:700">{text}</span>'


def _section(title: str, content: str, icon: str = "🔍") -> str:
    return f"""
    <details open>
      <summary style="cursor:pointer;font-size:1.1rem;font-weight:700;padding:10px 0;border-bottom:1px solid #334155;margin-bottom:12px">
        {icon} {title}
      </summary>
      <div style="padding:8px 0">{content}</div>
    </details>
    """


def _table(headers: list, rows: list) -> str:
    ths = "".join(f'<th style="padding:8px 12px;text-align:left;background:#1e293b;border-bottom:2px solid #334155">{h}</th>' for h in headers)
    trs = ""
    for i, row in enumerate(rows):
        bg = "#0f172a" if i % 2 == 0 else "#1e293b"
        tds = "".join(f'<td style="padding:8px 12px;border-bottom:1px solid #1e293b">{c}</td>' for c in row)
        trs += f'<tr style="background:{bg}">{tds}</tr>'
    return f'<table style="width:100%;border-collapse:collapse;font-size:14px"><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>'


def _render_subdomains(data):
    if not isinstance(data, list) or not data:
        return "<p style='color:#64748b'>No subdomains found.</p>"
    rows = [[item.get("subdomain",""), item.get("ip","")] if isinstance(item, dict) else [str(item),""] for item in data]
    return _table(["Subdomain", "IP"], rows)


def _render_headers(data):
    if not isinstance(data, dict): return ""
    rows = []
    for k, v in data.items():
        if isinstance(v, dict):
            risk  = v.get("risk","")
            color = _severity_color(risk)
            rows.append([k, v.get("value",""), _badge(risk, color)])
        else:
            rows.append([k, str(v), ""])
    return _table(["Header", "Value", "Risk"], rows)


def _render_ports(data):
    if not isinstance(data, list) or not data:
        return "<p style='color:#64748b'>No open ports found.</p>"
    rows = [[str(i.get("port","")), i.get("service",""), i.get("state","open")] for i in data if isinstance(i, dict)]
    return _table(["Port", "Service", "State"], rows)


def _render_dns(data):
    if not isinstance(data, dict): return ""
    rows = []
    for rtype, records in data.items():
        for r in records:
            rows.append([rtype, str(r)])
    return _table(["Type", "Value"], rows)


def _render_whois(data):
    if not isinstance(data, dict): return ""
    return _table(["Field", "Value"], [[k, str(v)] for k, v in data.items()])


def _render_tech(data):
    if not isinstance(data, dict): return ""
    rows = [[k, ", ".join(v) if isinstance(v, list) else str(v)] for k, v in data.items()]
    return _table(["Category", "Detected"], rows)


def _render_waf(data):
    if not isinstance(data, dict): return ""
    detected = data.get("detected", False)
    waf_name = data.get("waf", "None detected")
    color    = "#ef4444" if detected else "#22c55e"
    return f'<p style="font-size:1.1rem">{_badge(waf_name, color)}</p>'


def _render_email(data):
    if not isinstance(data, dict): return ""
    rows = []
    for k, v in data.items():
        if isinstance(v, dict):
            status = v.get("status","")
            color  = _severity_color(status)
            rows.append([k, _badge(status, color), v.get("value","")])
    return _table(["Check", "Status", "Value"], rows)


def _render_ssl(data):
    if not isinstance(data, dict) or "error" in data: return "<p style='color:#ef4444'>SSL scan failed.</p>"
    days  = data.get("days_left")
    dcolor = "#ef4444" if (days is not None and days < 30) else "#22c55e"
    info_rows = [
        ["Subject",  data.get("subject","")],
        ["Issuer",   data.get("issuer","")],
        ["Protocol", data.get("protocol","")],
        ["Cipher",   data.get("cipher","")],
        ["Expires",  data.get("not_after","")],
        ["Days Left", f'<span style="color:{dcolor};font-weight:700">{days}</span>' if days is not None else "N/A"],
    ]
    html = _table(["Field","Value"], info_rows)
    risks = data.get("risks",[])
    if risks:
        risk_rows = [[r.get("issue",""), _badge(r.get("severity",""), _severity_color(r.get("severity","")))] for r in risks]
        html += "<br>" + _table(["Risk","Severity"], risk_rows)
    return html


def _render_cors(data):
    if not isinstance(data, dict): return ""
    verdict = data.get("verdict","UNKNOWN")
    color   = _severity_color(verdict)
    html    = f'<p>{_badge(verdict, color)} &nbsp; {data.get("issue_count",0)} issue(s) found</p>'
    issues  = data.get("issues",[])
    if issues:
        rows = [[i.get("issue",""), _badge(i.get("severity",""), _severity_color(i.get("severity","")))] for i in issues]
        html += _table(["Issue","Severity"], rows)
    return html


def _render_cve(data):
    if not isinstance(data, dict) or not data.get("findings"): return "<p style='color:#22c55e'>No CVEs found.</p>"
    overall = data.get("overall_severity","NONE")
    html    = f'<p>{_badge(overall, _severity_color(overall))} &nbsp; {data.get("total_cves",0)} CVE(s) — source: {data.get("source","")}</p>'
    for finding in data["findings"]:
        rows = [[c.get("id",""), _badge(str(c.get("severity","")), _severity_color(str(c.get("severity","")))), c.get("description","")[:120]]
                for c in finding.get("cves",[])[:5]]
        html += f'<p style="margin:12px 0 4px;font-weight:600">{finding["tech"]}</p>' + _table(["CVE ID","Severity","Description"], rows)
    return html


def _render_robots(data):
    if not isinstance(data, dict): return ""
    robots  = data.get("robots",{})
    sitemap = data.get("sitemap",{})
    interesting = data.get("interesting",[])
    html = f"""
    <p>robots.txt: {'<span style="color:#22c55e">✔ found</span>' if robots.get('found') else '<span style="color:#64748b">not found</span>'}
    &nbsp;|&nbsp; sitemap.xml: {'<span style="color:#22c55e">✔ found</span>' if sitemap.get('found') else '<span style="color:#64748b">not found</span>'}
    &nbsp;|&nbsp; URLs in sitemap: {sitemap.get('url_count',0)}</p>
    """
    if interesting:
        html += _table(["Interesting Path"], [[p] for p in interesting[:30]])
    disallowed = robots.get("disallowed",[])
    if disallowed:
        html += "<br>" + _table(["Disallowed Path"], [[p] for p in disallowed[:20]])
    return html


def _render_risk_dashboard(risk: dict) -> str:
    score   = risk.get("score", 0)
    grade   = risk.get("grade", "A")
    color   = risk.get("color", "#22c55e")
    summary = risk.get("summary", {})
    total   = risk.get("total", 0)
    findings = risk.get("findings", [])

    # Donut chart data
    labels  = list(summary.keys())
    values  = list(summary.values())
    colors  = [_severity_color(l) for l in labels]

    # Findings table
    finding_rows = "".join(
        f'<tr style="background:{"#0f172a" if i%2==0 else "#1e293b"}">'
        f'<td style="padding:6px 10px">{f.get("module","")}</td>'
        f'<td style="padding:6px 10px">{f.get("issue","")}</td>'
        f'<td style="padding:6px 10px">{_badge(f.get("severity",""), _severity_color(f.get("severity","")))}</td>'
        f'</tr>'
        for i, f in enumerate(findings)
    )

    return f"""
    <div style="display:flex;gap:24px;flex-wrap:wrap;margin-bottom:24px;align-items:flex-start">

      <!-- Score card -->
      <div style="background:#1e293b;border-radius:12px;padding:24px;text-align:center;min-width:160px">
        <div style="font-size:4rem;font-weight:900;color:{color}">{grade}</div>
        <div style="font-size:2rem;font-weight:700;color:{color}">{score}<span style="font-size:1rem;color:#94a3b8">/100</span></div>
        <div style="color:#94a3b8;margin-top:4px">Risk Score</div>
      </div>

      <!-- Donut chart -->
      <div style="background:#1e293b;border-radius:12px;padding:24px;flex:1;min-width:260px">
        <div style="font-weight:700;margin-bottom:12px;color:#e2e8f0">Severity Breakdown</div>
        <canvas id="sevChart" height="180"></canvas>
      </div>

      <!-- Summary counts -->
      <div style="background:#1e293b;border-radius:12px;padding:24px;min-width:180px">
        <div style="font-weight:700;margin-bottom:12px;color:#e2e8f0">Finding Summary</div>
        {''.join(f'<div style="display:flex;justify-content:space-between;margin:6px 0"><span style="color:#94a3b8">{k}</span><span style="color:{_severity_color(k)};font-weight:700">{v}</span></div>' for k,v in summary.items())}
        <div style="border-top:1px solid #334155;margin-top:8px;padding-top:8px;display:flex;justify-content:space-between">
          <span style="color:#e2e8f0;font-weight:700">Total</span>
          <span style="color:#e2e8f0;font-weight:700">{total}</span>
        </div>
      </div>
    </div>

    <!-- Findings table with filter -->
    <div style="background:#1e293b;border-radius:12px;padding:20px;margin-bottom:24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <span style="font-weight:700;color:#e2e8f0">All Findings ({total})</span>
        <input id="filterInput" onkeyup="filterFindings()" placeholder="Filter findings..." 
          style="background:#0f172a;border:1px solid #334155;color:#e2e8f0;padding:6px 12px;border-radius:6px;width:200px">
      </div>
      <table id="findingsTable" style="width:100%;border-collapse:collapse;font-size:13px">
        <thead><tr>
          <th style="padding:8px 10px;text-align:left;background:#0f172a;border-bottom:2px solid #334155">Module</th>
          <th style="padding:8px 10px;text-align:left;background:#0f172a;border-bottom:2px solid #334155">Issue</th>
          <th style="padding:8px 10px;text-align:left;background:#0f172a;border-bottom:2px solid #334155">Severity</th>
        </tr></thead>
        <tbody>{finding_rows}</tbody>
      </table>
    </div>

    <script>
    // Donut chart
    const ctx = document.getElementById('sevChart').getContext('2d');
    new Chart(ctx, {{
      type: 'doughnut',
      data: {{
        labels: {json.dumps(labels)},
        datasets: [{{ data: {json.dumps(values)}, backgroundColor: {json.dumps(colors)}, borderWidth: 2, borderColor: '#1e293b' }}]
      }},
      options: {{ plugins: {{ legend: {{ labels: {{ color: '#e2e8f0' }} }} }}, cutout: '65%' }}
    }});

    // Filter
    function filterFindings() {{
      const q = document.getElementById('filterInput').value.toLowerCase();
      document.querySelectorAll('#findingsTable tbody tr').forEach(row => {{
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      }});
    }}
    </script>
    """


SECTION_RENDERERS = {
    "subdomains": ("Subdomains",        "🌐", _render_subdomains),
    "headers":    ("HTTP Headers",      "📋", _render_headers),
    "ports":      ("Open Ports",        "🔌", _render_ports),
    "dns":        ("DNS Records",       "📡", _render_dns),
    "whois":      ("WHOIS",             "📝", _render_whois),
    "tech":       ("Technology",        "⚙️",  _render_tech),
    "waf":        ("WAF Detection",     "🛡️",  _render_waf),
    "email":      ("Email Security",    "📧", _render_email),
    "ssl":        ("SSL/TLS",           "🔒", _render_ssl),
    "cors":       ("CORS",              "🌍", _render_cors),
    "cve":        ("CVE Lookup",        "🐛", _render_cve),
    "robots":     ("Robots / Sitemap",  "🤖", _render_robots),
}


def generate_html_report(results: dict, risk: dict) -> str:
    target    = results.get("target", "unknown")
    timestamp = results.get("timestamp", datetime.datetime.utcnow().isoformat())
    profile   = results.get("profile") or "manual"
    grade     = risk.get("grade","A")
    color     = risk.get("color","#22c55e")
    score     = risk.get("score", 0)

    # Build module sections
    sections_html = ""
    for key, (title, icon, renderer) in SECTION_RENDERERS.items():
        if key in results and not isinstance(results[key], type(None)):
            data = results[key]
            if isinstance(data, dict) and "error" in data:
                content = f'<p style="color:#ef4444">Error: {data["error"]}</p>'
            else:
                content = renderer(data)
            sections_html += _section(title, content, icon)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ne0 Report — {target}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif; padding: 24px; }}
    a {{ color: #60a5fa; }}
    details summary::-webkit-details-marker {{ display: none; }}
    details > summary::before {{ content: "▶ "; font-size: 0.8em; }}
    details[open] > summary::before {{ content: "▼ "; }}
    ::-webkit-scrollbar {{ width: 6px; }} ::-webkit-scrollbar-track {{ background: #1e293b; }}
    ::-webkit-scrollbar-thumb {{ background: #475569; border-radius: 3px; }}
  </style>
</head>
<body>
  <!-- Header -->
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:28px;flex-wrap:wrap;gap:12px">
    <div>
      <div style="font-size:1.8rem;font-weight:900;color:#38bdf8">🦉 Ne0</div>
      <div style="color:#94a3b8;font-size:0.9rem">External Attack Surface Report</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:1.2rem;font-weight:700;color:#e2e8f0">{target}</div>
      <div style="color:#64748b;font-size:0.8rem">{timestamp[:19].replace('T',' ')} UTC  |  profile: {profile}</div>
    </div>
  </div>

  <!-- Risk Dashboard -->
  <div style="background:#1e293b;border-radius:12px;padding:20px;margin-bottom:28px">
    <div style="font-size:1.2rem;font-weight:700;color:#38bdf8;margin-bottom:16px">📊 Risk Dashboard</div>
    {_render_risk_dashboard(risk)}
  </div>

  <!-- Module Sections -->
  <div style="background:#1e293b;border-radius:12px;padding:20px">
    <div style="font-size:1.2rem;font-weight:700;color:#38bdf8;margin-bottom:16px">🔍 Scan Results</div>
    {sections_html}
  </div>

  <div style="text-align:center;margin-top:24px;color:#475569;font-size:0.8rem">
    Generated by Ne0 · For authorized security testing only
  </div>
</body>
</html>"""


def save_html_report(results: dict, risk: dict, output_dir: str = ".") -> str:
    target    = results.get("target", "scan")
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename  = f"ne0_{target}_{timestamp}.html"
    path      = Path(output_dir) / filename
    path.write_text(generate_html_report(results, risk), encoding="utf-8")
    return str(path)
