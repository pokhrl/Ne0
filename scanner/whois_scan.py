import asyncio
import whois


async def scan_whois(target: str):
    loop = asyncio.get_event_loop()
    try:
        data = await loop.run_in_executor(None, lambda: whois.whois(target))
        results = {}

        fields = [
            "domain_name", "registrar", "whois_server",
            "creation_date", "expiration_date", "updated_date",
            "name_servers", "status", "emails", "org",
            "country", "dnssec",
        ]
        for field in fields:
            val = getattr(data, field, None)
            if val is None:
                continue
            if isinstance(val, list):
                # deduplicate and stringify
                seen = []
                for v in val:
                    sv = str(v)
                    if sv not in seen:
                        seen.append(sv)
                results[field] = ", ".join(seen)
            else:
                results[field] = str(val)

        return results
    except Exception as e:
        return {"error": str(e)}
