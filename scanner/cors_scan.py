"""
Ne0 - CORS Misconfiguration Scanner
Tests for common CORS misconfigurations that allow unauthorized cross-origin access.
"""

import asyncio
import aiohttp


# Origins to test against
TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://{target}.evil.com",   # subdomain bypass attempt
    "https://evil{target}",        # suffix bypass attempt
]

CORS_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
]


async def _test_origin(session: aiohttp.ClientSession, url: str, origin: str) -> dict:
    try:
        headers = {"Origin": origin}
        async with session.options(url, headers=headers, allow_redirects=True) as resp:
            acao  = resp.headers.get("Access-Control-Allow-Origin", "")
            acac  = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            aacm  = resp.headers.get("Access-Control-Allow-Methods", "")
            return {
                "origin_sent":   origin,
                "acao":          acao,
                "credentials":   acac == "true",
                "methods":       aacm,
                "status":        resp.status,
            }
    except Exception as e:
        return {"origin_sent": origin, "error": str(e)}


def _classify(result: dict, target: str) -> dict:
    acao  = result.get("acao", "")
    creds = result.get("credentials", False)
    issues = []

    if acao == "*":
        issues.append({"issue": "Wildcard CORS (*) — any origin allowed", "severity": "MEDIUM"})
        if creds:
            issues.append({"issue": "Wildcard + credentials=true (browsers block this but misconfigured)", "severity": "HIGH"})

    elif acao and acao not in ("", "null"):
        origin_sent = result.get("origin_sent", "")
        # Reflected origin — server echoed back our evil origin
        if acao == origin_sent and "evil" in origin_sent:
            sev = "CRITICAL" if creds else "HIGH"
            issues.append({"issue": f"Origin reflected: {acao}", "severity": sev})

    if acao == "null":
        issues.append({"issue": "CORS allows 'null' origin (sandbox/file bypass)", "severity": "HIGH"})

    result["issues"] = issues
    return result


async def scan_cors(target: str, timeout: int = 5) -> dict:
    url = f"https://{target}"
    findings = []
    all_issues = []

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=timeout)
    ) as session:
        origins = [o.replace("{target}", target) for o in TEST_ORIGINS]
        tasks   = [_test_origin(session, url, o) for o in origins]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, Exception):
            continue
        classified = _classify(res, target)
        findings.append(classified)
        all_issues.extend(classified.get("issues", []))

    # Overall verdict
    if any(i["severity"] == "CRITICAL" for i in all_issues):
        verdict = "CRITICAL"
    elif any(i["severity"] == "HIGH" for i in all_issues):
        verdict = "HIGH"
    elif any(i["severity"] == "MEDIUM" for i in all_issues):
        verdict = "MEDIUM"
    elif all_issues:
        verdict = "LOW"
    else:
        verdict = "SAFE"

    return {
        "verdict":    verdict,
        "issues":     all_issues,
        "issue_count": len(all_issues),
        "details":    findings,
    }
