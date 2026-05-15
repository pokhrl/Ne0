import asyncio

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP (submission)",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2222: "SSH (alt)",
    3000: "Dev server",
    3306: "MySQL",
    3389: "RDP",
    4443: "HTTPS (alt)",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    7001: "WebLogic",
    8000: "HTTP (alt)",
    8080: "HTTP proxy",
    8443: "HTTPS (alt)",
    8888: "Jupyter / alt HTTP",
    9200: "Elasticsearch",
    9300: "Elasticsearch cluster",
    27017: "MongoDB",
}


async def check_port(host: str, port: int, service: str, timeout: int, semaphore: asyncio.Semaphore):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"port": port, "service": service, "state": "open"}
        except Exception:
            return None


async def scan_ports(target: str, timeout: int = 3, max_tasks: int = 50):
    semaphore = asyncio.Semaphore(max_tasks)
    tasks = [
        check_port(target, port, service, timeout, semaphore)
        for port, service in COMMON_PORTS.items()
    ]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]
