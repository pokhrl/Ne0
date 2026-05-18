"""
Ne0 - Screenshot Scanner
Captures screenshots of live subdomains/targets using Playwright.
Saves PNGs to ./screenshots/<target>/ directory.

Requires: pip install playwright && playwright install chromium
"""

import asyncio
import os
from pathlib import Path
from datetime import datetime


SCREENSHOT_DIR = Path("screenshots")


async def _capture(target: str, url: str, out_path: Path, timeout: int) -> dict:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "url":    url,
            "status": "error",
            "error":  "Playwright not installed. Run: pip install playwright && playwright install chromium",
        }

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            page = await context.new_page()
            await page.set_viewport_size({"width": 1280, "height": 800})

            response = await page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
            status   = response.status if response else 0

            await page.screenshot(path=str(out_path), full_page=False)
            await browser.close()

            return {
                "url":         url,
                "status":      status,
                "screenshot":  str(out_path),
                "title":       await page.title() if page else "",
            }
    except Exception as e:
        return {"url": url, "status": "error", "error": str(e)}


async def scan_screenshots(target: str, subdomains: list | None = None, timeout: int = 10) -> dict:
    """
    Capture screenshots of the target and any discovered subdomains.

    Args:
        target:     Root domain (e.g. example.com)
        subdomains: List of subdomain dicts from scan_subdomains() — optional
        timeout:    Per-page timeout in seconds
    """
    # Build URL list
    urls = [f"https://{target}", f"http://{target}"]

    if subdomains:
        for item in subdomains[:10]:   # cap at 10 subdomains
            sub = item.get("subdomain", "") if isinstance(item, dict) else str(item)
            if sub and sub != target:
                urls.append(f"https://{sub}")

    # Deduplicate
    urls = list(dict.fromkeys(urls))

    # Output directory
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_dir   = SCREENSHOT_DIR / target / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    # Capture all screenshots concurrently (capped semaphore to avoid overload)
    semaphore = asyncio.Semaphore(3)

    async def _capture_safe(url: str) -> dict:
        async with semaphore:
            safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_") + ".png"
            out_path  = out_dir / safe_name
            return await _capture(target, url, out_path, timeout)

    results = await asyncio.gather(*[_capture_safe(u) for u in urls], return_exceptions=True)

    screenshots = []
    errors      = []
    for res in results:
        if isinstance(res, Exception):
            errors.append(str(res))
        elif res.get("status") == "error":
            errors.append(f"{res['url']}: {res.get('error','')}")
        else:
            screenshots.append(res)

    return {
        "output_dir":   str(out_dir),
        "captured":     len(screenshots),
        "screenshots":  screenshots,
        "errors":       errors,
    }
