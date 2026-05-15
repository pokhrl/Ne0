import json
import datetime
import os


def generate_report(results: dict, fmt: str = "json") -> str:
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    target = results.get("target", "unknown").replace(".", "_")
    os.makedirs("reports", exist_ok=True)

    if fmt == "json":
        path = f"reports/ne0_{target}_{timestamp}.json"
        with open(path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        return path

    elif fmt == "html":
        path = f"reports/ne0_{target}_{timestamp}.html"
        html = _build_html(results)
        with open(path, "w") as f:
            f.write(html)
        return path

    return ""


def _section(title: str, content: str) -> str:
    return f"""
    <div class="section">
      <h2>{title}</h2>
      {content}
    </div>"""


def _table(headers: list, rows: list) -> str:
    th = "".join(f"<th>{h}</th>" for h in headers)
    tbody = ""
    for row in rows:
        td = "".join(f"<td>{cell}</td>" for cell in row)
        tbody += f"<tr>{td}</tr>"
    return f"<table><thead><tr>{th}</tr></thead><tbody>{tbody}</tbody></table>"


def _risk_badge(risk: str) -> str:
    colors = {"HIGH": "#e74c3c", "MEDIUM": "#e67e22", "LOW": "#f1c40f", "INFO": "#3498db", "PASS": "#2ecc71", "FAIL": "#e74c3c", "WARN": "#e67e22"}
    color = colors.get(risk, "#95a5a6")
    return f'<span class="badge" style="background:{color}">{risk}</span>'


def _build_html(results: dict) -> str:
    target = results.get("target", "")
    ts = results.get("timestamp", "")
    sections = ""

    # Subdomains
    if "subdomains" in results:
        data = results["subdomains"]
        rows = [[item.get("subdomain",""), item.get("ip","")] for item in data if isinstance(item, dict)]
        sections += _section("Subdomains", _table(["Subdomain", "IP"], rows))

    # Headers
    if "headers" in results:
        data = results["headers"]
        rows = []
        for k, v in data.items():
            if isinstance(v, dict):
                rows.append([k, v.get("value",""), _risk_badge(v.get("risk",""))])
        sections += _section("HTTP Headers", _table(["Header", "Value", "Risk"], rows))

    # Ports
    if "ports" in results:
        data = results["ports"]
        rows = [[str(p.get("port","")), p.get("service",""), p.get("state","")] for p in data if isinstance(p, dict)]
        sections += _section("Open Ports", _table(["Port", "Service", "State"], rows))

    # DNS
    if "dns" in results:
        data = results["dns"]
        rows = []
        for rtype, records in data.items():
            for r in records:
                rows.append([rtype, r])
        sections += _section("DNS Records", _table(["Type", "Value"], rows))

    # WHOIS
    if "whois" in results:
        data = results["whois"]
        rows = [[k, str(v)] for k, v in data.items()]
        sections += _section("WHOIS", _table(["Field", "Value"], rows))

    # Tech
    if "tech" in results:
        data = results["tech"]
        rows = [[k, ", ".join(v) if isinstance(v, list) else str(v)] for k, v in data.items()]
        sections += _section("Technology Fingerprint", _table(["Category", "Detected"], rows))

    # WAF
    if "waf" in results:
        data = results["waf"]
        waf = data.get("waf", "None detected")
        detected = data.get("detected", False)
        color = "#e74c3c" if detected else "#2ecc71"
        sections += _section("WAF Detection", f'<p style="color:{color};font-weight:bold;font-size:1.2em">{waf}</p>')

    # Email
    if "email" in results:
        data = results["email"]
        rows = []
        for k, v in data.items():
            if isinstance(v, dict):
                rows.append([k, _risk_badge(v.get("status","")), v.get("value","")])
        sections += _section("Email Security", _table(["Check", "Status", "Value"], rows))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ne0 Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  header {{ border-bottom: 1px solid #30363d; padding-bottom: 1rem; margin-bottom: 2rem; }}
  header h1 {{ color: #58a6ff; font-size: 2rem; }}
  header p {{ color: #8b949e; margin-top: 0.3rem; }}
  .section {{ margin-bottom: 2rem; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; }}
  .section h2 {{ color: #58a6ff; margin-bottom: 1rem; font-size: 1.1rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th {{ background: #1c2128; color: #8b949e; text-align: left; padding: 8px 12px; border-bottom: 1px solid #30363d; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; word-break: break-all; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1c2128; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: #fff; }}
  footer {{ text-align: center; color: #8b949e; font-size: 0.8rem; margin-top: 3rem; }}
</style>
</head>
<body>
<header>
  <h1>Ne0 — Attack Surface Report</h1>
  <p>Target: <strong style="color:#c9d1d9">{target}</strong> &nbsp;|&nbsp; Scanned: {ts}</p>
</header>
{sections}
<footer>Generated by Ne0 — for authorized security testing only</footer>
</body>
</html>"""
