import asyncio
import dns.resolver
import dns.exception


async def scan_dns(target: str):
    results = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    loop = asyncio.get_event_loop()

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    async def query(rtype):
        try:
            answers = await loop.run_in_executor(
                None, lambda: resolver.resolve(target, rtype)
            )
            return rtype, [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            return rtype, []
        except dns.resolver.NXDOMAIN:
            return rtype, ["NXDOMAIN"]
        except dns.exception.DNSException:
            return rtype, []
        except Exception as e:
            return rtype, [f"error: {e}"]

    tasks = [query(rt) for rt in record_types]
    raw = await asyncio.gather(*tasks)

    for rtype, records in raw:
        if records:
            results[rtype] = records

    return results
