"""
Ne0 - CVE Lookup Scanner
Matches technology versions detected by tech_scan against the NVD CVE API.
Falls back to a curated offline list if the API is unavailable.
"""

import asyncio
import aiohttp
import re


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Offline fallback — well-known CVEs for common tech
OFFLINE_CVE_DB = {
    "apache": [
        {"id": "CVE-2021-41773", "description": "Path traversal and RCE in Apache 2.4.49", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2021-42013", "description": "Path traversal bypass in Apache 2.4.49-2.4.50", "severity": "CRITICAL", "cvss": 9.8},
    ],
    "nginx": [
        {"id": "CVE-2021-23017", "description": "1-byte memory overwrite in nginx resolver", "severity": "HIGH", "cvss": 7.7},
    ],
    "php": [
        {"id": "CVE-2024-4577", "description": "Argument injection vulnerability in PHP CGI", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2023-3824", "description": "Buffer overflow in phar extension", "severity": "HIGH", "cvss": 7.5},
    ],
    "wordpress": [
        {"id": "CVE-2023-2745", "description": "Directory traversal in WordPress core", "severity": "MEDIUM", "cvss": 5.4},
        {"id": "CVE-2022-21661", "description": "SQL injection via WP_Query", "severity": "HIGH", "cvss": 8.0},
    ],
    "jquery": [
        {"id": "CVE-2020-11022", "description": "XSS via HTML containing <option> elements", "severity": "MEDIUM", "cvss": 6.1},
        {"id": "CVE-2019-11358", "description": "Prototype pollution via Object.extend", "severity": "MEDIUM", "cvss": 6.1},
    ],
    "openssl": [
        {"id": "CVE-2022-0778", "description": "Infinite loop in BN_mod_sqrt()", "severity": "HIGH", "cvss": 7.5},
        {"id": "CVE-2021-3449", "description": "NULL pointer deref via malformed renegotiation", "severity": "HIGH", "cvss": 7.5},
    ],
    "drupal": [
        {"id": "CVE-2018-7600", "description": "Drupalgeddon2 — RCE in Drupal core", "severity": "CRITICAL", "cvss": 9.8},
    ],
    "laravel": [
        {"id": "CVE-2021-3129", "description": "RCE via debug mode + Ignition", "severity": "CRITICAL", "cvss": 9.8},
    ],
    "iis": [
        {"id": "CVE-2017-7269", "description": "Buffer overflow in WebDAV on IIS 6.0", "severity": "CRITICAL", "cvss": 9.8},
    ],
    "tomcat": [
        {"id": "CVE-2020-1938", "description": "Ghostcat — AJP file read/inclusion", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2019-0232",  "description": "RCE via CGI on Windows", "severity": "CRITICAL", "cvss": 9.8},
    ],
}


async def _nvd_lookup(session: aiohttp.ClientSession, keyword: str, timeout: int) -> list:
    """Query NVD API for CVEs matching a keyword."""
    try:
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        async with session.get(NVD_API, params=params,
                               timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve   = item.get("cve", {})
                cve_id = cve.get("id", "")
                descs  = cve.get("descriptions", [])
                desc   = next((d["value"] for d in descs if d["lang"] == "en"), "")
                metrics = cve.get("metrics", {})
                cvss_score = None
                severity   = "UNKNOWN"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0].get("cvssData", {})
                        cvss_score = m.get("baseScore")
                        severity   = m.get("baseSeverity", "UNKNOWN")
                        break
                cves.append({"id": cve_id, "description": desc[:200], "severity": severity, "cvss": cvss_score})
            return cves
    except Exception:
        return []


def _offline_lookup(tech: str) -> list:
    tech_lower = tech.lower()
    for key, cves in OFFLINE_CVE_DB.items():
        if key in tech_lower:
            return cves
    return []


async def scan_cve(target: str, tech_results: dict | None = None, timeout: int = 5) -> dict:
    """
    Accepts tech_results from scan_tech() to look up CVEs per detected technology.
    If tech_results is None, returns an empty result with a message.
    """
    if not tech_results:
        return {"note": "Run --tech before --cve for best results", "findings": []}

    # Flatten all detected tech values into a list of strings
    tech_list = []
    for category, values in tech_results.items():
        if isinstance(values, list):
            tech_list.extend(values)
        elif isinstance(values, str) and values:
            tech_list.append(values)

    if not tech_list:
        return {"note": "No technologies detected to look up", "findings": []}

    findings  = []
    all_cves  = []
    nvd_used  = False

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Try NVD first (rate-limited to 5 req/30s without API key)
        tasks = [_nvd_lookup(session, tech, timeout) for tech in tech_list[:5]]
        nvd_results = await asyncio.gather(*tasks, return_exceptions=True)

        for tech, nvd_cves in zip(tech_list[:5], nvd_results):
            if isinstance(nvd_cves, list) and nvd_cves:
                nvd_used = True
                findings.append({"tech": tech, "source": "NVD", "cves": nvd_cves})
                all_cves.extend(nvd_cves)
            else:
                # Fallback to offline DB
                offline = _offline_lookup(tech)
                if offline:
                    findings.append({"tech": tech, "source": "offline", "cves": offline})
                    all_cves.extend(offline)

    # Overall severity
    severities = [c.get("severity", "").upper() for c in all_cves]
    if "CRITICAL" in severities:
        overall = "CRITICAL"
    elif "HIGH" in severities:
        overall = "HIGH"
    elif "MEDIUM" in severities:
        overall = "MEDIUM"
    elif "LOW" in severities:
        overall = "LOW"
    else:
        overall = "NONE"

    return {
        "overall_severity": overall,
        "total_cves":       len(all_cves),
        "source":           "NVD" if nvd_used else "offline",
        "findings":         findings,
    }
