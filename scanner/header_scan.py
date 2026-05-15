import asyncio
import aiohttp
 
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "risk": "HIGH",
        "desc": "HSTS missing — site may be vulnerable to protocol downgrade attacks"
    },
    "Content-Security-Policy": {
        "risk": "HIGH",
        "desc": "CSP missing — increases XSS risk"
    },
    "X-Frame-Options": {
        "risk": "MEDIUM",
        "desc": "Clickjacking protection missing"
    },
    "X-Content-Type-Options": {
        "risk": "MEDIUM",
        "desc": "MIME sniffing protection missing"
    },
    "Referrer-Policy": {
        "risk": "LOW",
        "desc": "Referrer leakage possible"
    },
    "Permissions-Policy": {
        "risk": "LOW",
        "desc": "Browser feature policy not set"
    },
    "X-XSS-Protection": {
        "risk": "LOW",
        "desc": "Legacy XSS filter header missing (informational)"
    },
}
 
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
 
 
async def scan_headers(target: str, timeout: int = 5):
    results = {}
    url = f"https://{target}"
    fallback = f"http://{target}"
 
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True) as resp:
                    headers = dict(resp.headers)
            except Exception:
                async with session.get(fallback, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True) as resp:
                    headers = dict(resp.headers)
 
        # Check security headers presence
        for header, meta in SECURITY_HEADERS.items():
            if header in headers:
                results[header] = {
                    "value": headers[header],
                    "risk": "INFO",
                    "desc": "Present"
                }
            else:
                results[header] = {
                    "value": "MISSING",
                    "risk": meta["risk"],
                    "desc": meta["desc"]
                }
 
        # Flag leaky headers
        for header in LEAKY_HEADERS:
            if header in headers:
                results[header] = {
                    "value": headers[header],
                    "risk": "MEDIUM",
                    "desc": "Server info disclosure"
                }
 
    except Exception as e:
        results["error"] = {"value": str(e), "risk": "INFO", "desc": "Could not connect"}
 
    return results
 
