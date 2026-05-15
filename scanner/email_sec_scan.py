import asyncio
import dns.resolver
import dns.exception


async def scan_email_security(target: str):
    results = {}
    loop = asyncio.get_event_loop()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    async def query_txt(name):
        try:
            answers = await loop.run_in_executor(
                None, lambda: resolver.resolve(name, "TXT")
            )
            return [str(r).strip('"') for r in answers]
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except Exception:
            return []

    # SPF check
    spf_records = await query_txt(target)
    spf_found = [r for r in spf_records if r.startswith("v=spf1")]
    if spf_found:
        spf_val = spf_found[0]
        if "-all" in spf_val:
            status = "PASS"
        elif "~all" in spf_val:
            status = "WARN"
        else:
            status = "WARN"
        results["SPF"] = {"status": status, "value": spf_val}
    else:
        results["SPF"] = {"status": "FAIL", "value": "No SPF record found"}

    # DMARC check
    dmarc_records = await query_txt(f"_dmarc.{target}")
    dmarc_found = [r for r in dmarc_records if "v=DMARC1" in r]
    if dmarc_found:
        dmarc_val = dmarc_found[0]
        if "p=reject" in dmarc_val:
            status = "PASS"
        elif "p=quarantine" in dmarc_val:
            status = "WARN"
        else:
            status = "WARN"
        results["DMARC"] = {"status": status, "value": dmarc_val}
    else:
        results["DMARC"] = {"status": "FAIL", "value": "No DMARC record found"}

    # DKIM — try common selectors
    dkim_selectors = ["default", "google", "mail", "dkim", "k1", "s1", "s2", "selector1", "selector2"]
    dkim_found = None
    for selector in dkim_selectors:
        records = await query_txt(f"{selector}._domainkey.{target}")
        dkim_hits = [r for r in records if "v=DKIM1" in r or "p=" in r]
        if dkim_hits:
            dkim_found = {"selector": selector, "value": dkim_hits[0]}
            break

    if dkim_found:
        results["DKIM"] = {
            "status": "PASS",
            "value": f"selector={dkim_found['selector']} | {dkim_found['value'][:80]}..."
        }
    else:
        results["DKIM"] = {
            "status": "WARN",
            "value": f"No DKIM found for common selectors ({', '.join(dkim_selectors[:5])}...)"
        }

    # MTA-STS check
    mta_records = await query_txt(f"_mta-sts.{target}")
    mta_found = [r for r in mta_records if "v=STSv1" in r]
    if mta_found:
        results["MTA-STS"] = {"status": "PASS", "value": mta_found[0]}
    else:
        results["MTA-STS"] = {"status": "WARN", "value": "MTA-STS not configured"}

    # BIMI check
    bimi_records = await query_txt(f"default._bimi.{target}")
    bimi_found = [r for r in bimi_records if "v=BIMI1" in r]
    if bimi_found:
        results["BIMI"] = {"status": "PASS", "value": bimi_found[0]}
    else:
        results["BIMI"] = {"status": "INFO", "value": "BIMI not configured (optional)"}

    return results
