"""
Ne0 - Risk Scoring Engine
Assigns a unified risk score to every scan result.
Score: 0-100  |  Grade: A (safe) -> F (critical)
"""

SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":       3,
    "INFO":      1,
}


def _grade(score: int) -> tuple:
    if score == 0:   return "A", "#22c55e"
    elif score <= 10: return "B", "#86efac"
    elif score <= 25: return "C", "#facc15"
    elif score <= 50: return "D", "#f97316"
    else:             return "F", "#ef4444"


def _score_ssl(data):
    findings = []
    for r in data.get("risks", []):
        findings.append({"module": "SSL/TLS", "issue": r.get("issue", ""), "severity": r.get("severity", "LOW")})
    days = data.get("days_left")
    if days is not None and days < 0:
        findings.append({"module": "SSL/TLS", "issue": "Certificate expired", "severity": "CRITICAL"})
    elif days is not None and days < 30:
        findings.append({"module": "SSL/TLS", "issue": f"Certificate expiring in {days} days", "severity": "HIGH"})
    return findings


def _score_cors(data):
    return [{"module": "CORS", "issue": i.get("issue", ""), "severity": i.get("severity", "LOW")}
            for i in data.get("issues", [])]


def _score_headers(data):
    findings = []
    for header, v in data.items():
        if isinstance(v, dict):
            risk = v.get("risk", "")
            if risk in SEVERITY_WEIGHTS:
                findings.append({"module": "Headers", "issue": f"Header: {header}", "severity": risk})
    return findings


def _score_cve(data):
    findings = []
    for f in data.get("findings", []):
        for cve in f.get("cves", []):
            sev = str(cve.get("severity", "")).upper()
            if sev in SEVERITY_WEIGHTS:
                findings.append({"module": "CVE", "issue": f"{cve.get('id','')} ({f.get('tech','')})", "severity": sev})
    return findings


def _score_ports(data):
    risky = {21: "FTP", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL",
             27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
    findings = []
    for item in data:
        port = item.get("port")
        if port in risky:
            findings.append({"module": "Ports", "issue": f"Sensitive port open: {port} ({risky[port]})", "severity": "MEDIUM"})
    return findings


def _score_email(data):
    findings = []
    for check, v in data.items():
        if isinstance(v, dict) and v.get("status") == "FAIL":
            findings.append({"module": "Email", "issue": f"{check} missing/invalid", "severity": "MEDIUM"})
    return findings


def _score_waf(data):
    if not data.get("detected"):
        return [{"module": "WAF", "issue": "No WAF detected", "severity": "LOW"}]
    return []


def _score_robots(data):
    return [{"module": "Robots", "issue": f"Sensitive path exposed: {p}", "severity": "LOW"}
            for p in data.get("interesting", [])]


def calculate_risk(results: dict) -> dict:
    all_findings = []
    if "ssl"     in results and isinstance(results["ssl"], dict):     all_findings.extend(_score_ssl(results["ssl"]))
    if "cors"    in results and isinstance(results["cors"], dict):    all_findings.extend(_score_cors(results["cors"]))
    if "headers" in results and isinstance(results["headers"], dict): all_findings.extend(_score_headers(results["headers"]))
    if "cve"     in results and isinstance(results["cve"], dict):     all_findings.extend(_score_cve(results["cve"]))
    if "ports"   in results and isinstance(results["ports"], list):   all_findings.extend(_score_ports(results["ports"]))
    if "email"   in results and isinstance(results["email"], dict):   all_findings.extend(_score_email(results["email"]))
    if "waf"     in results and isinstance(results["waf"], dict):     all_findings.extend(_score_waf(results["waf"]))
    if "robots"  in results and isinstance(results["robots"], dict):  all_findings.extend(_score_robots(results["robots"]))

    score = min(100, sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in all_findings))
    grade, color = _grade(score)
    summary = {s: 0 for s in SEVERITY_WEIGHTS}
    for f in all_findings:
        summary[f.get("severity", "INFO")] = summary.get(f.get("severity", "INFO"), 0) + 1

    return {"score": score, "grade": grade, "color": color,
            "findings": all_findings, "summary": summary, "total": len(all_findings)}
