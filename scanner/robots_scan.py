"""
Ne0 - Robots.txt & Sitemap Scanner
Parses robots.txt and sitemap.xml to discover hidden paths and interesting endpoints.
"""

import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree


# Patterns that suggest sensitive or interesting paths
SENSITIVE_PATTERNS = [
    "admin", "login", "dashboard", "config", "backup", "db",
    "database", "secret", "private", "internal", "api", "test",
    "dev", "staging", "debug", "upload", "export", "import",
    ".env", ".git", "wp-admin", "phpmyadmin", "cpanel", "panel",
    "manage", "console", "shell", "passwd", "password", "token",
]


def _is_sensitive(path: str) -> bool:
    path_lower = path.lower()
    return any(p in path_lower for p in SENSITIVE_PATTERNS)


def _classify_path(path: str) -> str:
    if _is_sensitive(path):
        return "INTERESTING"
    return "NORMAL"


async def _fetch(session: aiohttp.ClientSession, url: str, timeout: int) -> str | None:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout),
                               allow_redirects=True) as resp:
            if resp.status == 200:
                return await resp.text(errors="ignore")
            return None
    except Exception:
        return None


def _parse_robots(content: str) -> dict:
    disallowed = []
    allowed    = []
    sitemaps   = []

    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
        elif line.lower().startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                allowed.append(path)
        elif line.lower().startswith("sitemap:"):
            url = line.split(":", 1)[1].strip()
            if url:
                sitemaps.append(url)

    return {"disallowed": disallowed, "allowed": allowed, "sitemaps": sitemaps}


def _parse_sitemap(content: str, base_url: str) -> list:
    urls = []
    try:
        root = ElementTree.fromstring(content)
        ns   = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        for loc in root.findall(".//sm:loc", ns):
            if loc.text:
                urls.append(loc.text.strip())
        # If no namespace worked, try without
        if not urls:
            for loc in root.iter("loc"):
                if loc.text:
                    urls.append(loc.text.strip())
    except Exception:
        pass
    return urls


async def scan_robots(target: str, timeout: int = 5) -> dict:
    base_url  = f"https://{target}"
    robots_url  = urljoin(base_url, "/robots.txt")
    sitemap_url = urljoin(base_url, "/sitemap.xml")

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        robots_content, sitemap_content = await asyncio.gather(
            _fetch(session, robots_url, timeout),
            _fetch(session, sitemap_url, timeout),
        )

        # ── Parse robots.txt ──────────────────────────────────────────────────
        robots_data = {"found": False, "disallowed": [], "allowed": [], "sitemaps": []}
        if robots_content:
            robots_data["found"] = True
            parsed = _parse_robots(robots_content)
            robots_data.update(parsed)

        # ── Parse sitemap.xml ─────────────────────────────────────────────────
        sitemap_data = {"found": False, "urls": [], "url_count": 0}
        sitemap_urls = []
        if sitemap_content:
            sitemap_data["found"] = True
            sitemap_urls = _parse_sitemap(sitemap_content, base_url)
            sitemap_data["urls"]      = sitemap_urls[:50]   # cap at 50
            sitemap_data["url_count"] = len(sitemap_urls)

        # ── Also fetch sitemaps referenced in robots.txt ──────────────────────
        extra_sitemap_urls = []
        for sm_url in robots_data.get("sitemaps", [])[:3]:
            sm_content = await _fetch(session, sm_url, timeout)
            if sm_content:
                extra_sitemap_urls.extend(_parse_sitemap(sm_content, base_url))

    # ── Combine all paths and flag interesting ones ───────────────────────────
    all_paths = (
        robots_data.get("disallowed", []) +
        robots_data.get("allowed", []) +
        [urlparse(u).path for u in sitemap_urls + extra_sitemap_urls]
    )

    interesting = []
    for path in all_paths:
        if _classify_path(path) == "INTERESTING":
            interesting.append(path)

    # Deduplicate
    interesting = list(dict.fromkeys(interesting))

    return {
        "robots":      robots_data,
        "sitemap":     sitemap_data,
        "interesting": interesting,
        "interesting_count": len(interesting),
    }
