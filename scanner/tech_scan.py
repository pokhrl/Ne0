import asyncio
import re
import aiohttp

# Signatures: (pattern_to_match_in_headers_or_body, category, name)
SIGNATURES = [
    # Web servers
    ({"header": "Server", "pattern": r"nginx"},               "Web Server",  "Nginx"),
    ({"header": "Server", "pattern": r"Apache"},              "Web Server",  "Apache"),
    ({"header": "Server", "pattern": r"Microsoft-IIS"},       "Web Server",  "IIS"),
    ({"header": "Server", "pattern": r"LiteSpeed"},           "Web Server",  "LiteSpeed"),
    ({"header": "Server", "pattern": r"cloudflare"},          "CDN",         "Cloudflare"),
    ({"header": "Server", "pattern": r"AmazonS3"},            "Cloud",       "AWS S3"),

    # Frameworks / languages
    ({"header": "X-Powered-By", "pattern": r"PHP"},           "Language",    "PHP"),
    ({"header": "X-Powered-By", "pattern": r"ASP\.NET"},      "Framework",   "ASP.NET"),
    ({"header": "X-Powered-By", "pattern": r"Express"},       "Framework",   "Express.js"),
    ({"header": "X-Powered-By", "pattern": r"Next\.js"},      "Framework",   "Next.js"),

    # CDN / proxies
    ({"header": "Via", "pattern": r"cloudfront"},             "CDN",         "AWS CloudFront"),
    ({"header": "X-Cache", "pattern": r"HIT|MISS"},           "CDN",         "CDN Cache"),
    ({"header": "CF-Ray", "pattern": r".+"},                  "CDN",         "Cloudflare"),
    ({"header": "X-Sucuri-ID", "pattern": r".+"},             "WAF/CDN",     "Sucuri"),

    # CMS (body-based)
    ({"body": r"wp-content|wp-includes|wordpress"},           "CMS",         "WordPress"),
    ({"body": r"/sites/default/files|Drupal"},                "CMS",         "Drupal"),
    ({"body": r"Joomla|joomla"},                              "CMS",         "Joomla"),
    ({"body": r"shopify"},                                    "E-commerce",  "Shopify"),
    ({"body": r"woocommerce"},                                "E-commerce",  "WooCommerce"),
    ({"body": r"Magento|mage"},                               "E-commerce",  "Magento"),

    # Analytics / tracking
    ({"body": r"google-analytics\.com|gtag\("},               "Analytics",   "Google Analytics"),
    ({"body": r"googletagmanager\.com"},                      "Analytics",   "Google Tag Manager"),
    ({"body": r"hotjar\.com"},                                "Analytics",   "Hotjar"),

    # JavaScript frameworks
    ({"body": r"react\.production|__REACT"},                  "JS Framework","React"),
    ({"body": r"vue\.min\.js|Vue\.js"},                       "JS Framework","Vue.js"),
    ({"body": r"angular\.min\.js|ng-version"},                "JS Framework","Angular"),
    ({"body": r"jquery[\.\-][\d]"},                          "JS Library",  "jQuery"),

    # Security
    ({"header": "X-Frame-Options", "pattern": r".+"},         "Security",    "X-Frame-Options"),
    ({"header": "Strict-Transport-Security", "pattern": r".+"},"Security",   "HSTS"),
]


async def scan_tech(target: str, timeout: int = 5):
    url = f"https://{target}"
    fallback = f"http://{target}"
    detected = {}

    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True) as resp:
                    headers = dict(resp.headers)
                    body = await resp.text(errors="ignore")
            except Exception:
                async with session.get(fallback, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True) as resp:
                    headers = dict(resp.headers)
                    body = await resp.text(errors="ignore")

        for sig in SIGNATURES:
            rule = sig[0]
            category = sig[1]
            name = sig[2]

            if "header" in rule:
                val = headers.get(rule["header"], "")
                if re.search(rule["pattern"], val, re.IGNORECASE):
                    detected.setdefault(category, [])
                    if name not in detected[category]:
                        detected[category].append(name)
            elif "body" in rule:
                if re.search(rule["body"], body, re.IGNORECASE):
                    detected.setdefault(category, [])
                    if name not in detected[category]:
                        detected[category].append(name)

    except Exception as e:
        detected["error"] = [str(e)]

    return detected
