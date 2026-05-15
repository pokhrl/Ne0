import asyncio
import socket
import dns.resolver
 
WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "beta",
    "vpn", "remote", "portal", "app", "blog", "shop", "store", "support",
    "help", "cdn", "static", "assets", "img", "media", "ns1", "ns2",
    "smtp", "pop", "imap", "mx", "webmail", "cpanel", "whm", "autodiscover",
    "autoconfig", "auth", "login", "secure", "gateway", "proxy", "git",
    "gitlab", "github", "jenkins", "ci", "dashboard", "monitor", "status",
    "docs", "wiki", "kb", "forum", "community", "chat", "meet", "video",
    "m", "mobile", "wap", "old", "new", "v1", "v2", "internal",
    "intranet", "extranet", "corp", "office", "hr", "finance", "crm",
    "erp", "backup", "files", "download", "upload", "data", "db",
    "database", "mysql", "postgres", "redis", "elastic", "search",
    "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "docker",
]
 
 
async def resolve_subdomain(subdomain: str, target: str, timeout: int, semaphore: asyncio.Semaphore):
    async with semaphore:
        fqdn = f"{subdomain}.{target}"
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None, lambda: socket.gethostbyname(fqdn)
            )
            return {"subdomain": fqdn, "ip": result}
        except Exception:
            return None
 
 
async def scan_subdomains(target: str, timeout: int = 5, max_tasks: int = 50):
    semaphore = asyncio.Semaphore(max_tasks)
    tasks = [resolve_subdomain(w, target, timeout, semaphore) for w in WORDLIST]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]
 
