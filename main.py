import argparse
import asyncio
import datetime

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from scanner.subdomain_scan   import scan_subdomains
from scanner.header_scan      import scan_headers
from scanner.port_scan        import scan_ports
from scanner.dns_scan         import scan_dns
from scanner.whois_scan       import scan_whois
from scanner.tech_scan        import scan_tech
from scanner.waf_scan         import scan_waf
from scanner.email_sec_scan   import scan_email_security
from scanner.ssl_scan         import scan_ssl
from scanner.cors_scan        import scan_cors
from scanner.cve_scan         import scan_cve
from scanner.robots_scan      import scan_robots
from scanner.screenshot_scan  import scan_screenshots
from utils.report   import generate_report
from utils.profiles import (
    get_profile, list_profiles,
    save_profile, delete_profile, apply_profile,
)

console = Console()

BANNER = """
[bold cyan]
 ███╗   ██╗███████╗ ██████╗ 
 ████╗  ██║██╔════╝██╔═══██╗
 ██╔██╗ ██║█████╗  ██║   ██║
 ██║╚██╗██║██╔══╝  ██║   ██║
 ██║ ╚████║███████╗╚██████╔╝
 ╚═╝  ╚═══╝╚══════╝ ╚═════╝ 
[/bold cyan][dim]External Attack Surface Discovery[/dim]
[dim]For authorized security testing only[/dim]
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Ne0 - External attack surface discovery tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Profiles:
  --profile quick      Fast recon (DNS, headers, WAF, tech)
  --profile deep       Full recon, all modules, HTML report
  --profile stealth    Low-noise, slow, minimal footprint
  --profile web        Web-focused (headers, tech, WAF, email)
  --profile network    Network-focused (subdomains, ports, DNS)

  --list-profiles                    Show all available profiles
  --save-profile NAME [--desc TEXT]  Save current flags as a profile
  --delete-profile NAME              Delete a custom profile
        """
    )

    parser.add_argument("target", nargs="?", help="Target domain (e.g. example.com)")

    pg = parser.add_argument_group("Profiles")
    pg.add_argument("--profile",        metavar="NAME", help="Run a named scan profile")
    pg.add_argument("--list-profiles",  action="store_true", help="List all profiles and exit")
    pg.add_argument("--save-profile",   metavar="NAME", help="Save current flags as a custom profile")
    pg.add_argument("--desc",           metavar="TEXT", default="", help="Description for --save-profile")
    pg.add_argument("--delete-profile", metavar="NAME", help="Delete a custom profile")

    # Original modules
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    parser.add_argument("--headers",    action="store_true", help="Scan HTTP headers")
    parser.add_argument("--ports",      action="store_true", help="Scan common ports")
    parser.add_argument("--dns",        action="store_true", help="Enumerate DNS records")
    parser.add_argument("--whois",      action="store_true", help="WHOIS lookup")
    parser.add_argument("--tech",       action="store_true", help="Technology fingerprinting")
    parser.add_argument("--waf",        action="store_true", help="WAF detection")
    parser.add_argument("--email",      action="store_true", help="Email security (SPF/DKIM/DMARC)")

    # New Phase 1 modules
    parser.add_argument("--ssl",        action="store_true", help="Deep SSL/TLS analysis")
    parser.add_argument("--cors",       action="store_true", help="CORS misconfiguration check")
    parser.add_argument("--cve",        action="store_true", help="CVE lookup for detected technologies")
    parser.add_argument("--robots",     action="store_true", help="Parse robots.txt & sitemap.xml")
    parser.add_argument("--screenshot", action="store_true", help="Screenshot live targets (needs playwright)")

    parser.add_argument("--all",        action="store_true", help="Run all modules")
    parser.add_argument("--output",  choices=["json", "html"], help="Save report (json or html)")
    parser.add_argument("--timeout", type=int, default=5,  help="Request timeout in seconds (default: 5)")
    parser.add_argument("--threads", type=int, default=50, help="Max concurrent tasks (default: 50)")

    return parser.parse_args()


async def run_scans(args):
    results = {
        "target":    args.target,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "profile":   getattr(args, "_active_profile", None),
    }
    run_all = args.all
    tasks = {}

    if run_all or args.subdomains:
        tasks["subdomains"] = scan_subdomains(args.target, args.timeout, args.threads)
    if run_all or args.headers:
        tasks["headers"]    = scan_headers(args.target, args.timeout)
    if run_all or args.ports:
        tasks["ports"]      = scan_ports(args.target, args.timeout, args.threads)
    if run_all or args.dns:
        tasks["dns"]        = scan_dns(args.target)
    if run_all or args.whois:
        tasks["whois"]      = scan_whois(args.target)
    if run_all or args.tech:
        tasks["tech"]       = scan_tech(args.target, args.timeout)
    if run_all or args.waf:
        tasks["waf"]        = scan_waf(args.target, args.timeout)
    if run_all or args.email:
        tasks["email"]      = scan_email_security(args.target)
    if run_all or args.ssl:
        tasks["ssl"]        = scan_ssl(args.target, args.timeout)
    if run_all or args.cors:
        tasks["cors"]       = scan_cors(args.target, args.timeout)
    if run_all or args.robots:
        tasks["robots"]     = scan_robots(args.target, args.timeout)

    if not tasks and not (run_all or args.cve or args.screenshot):
        console.print("[yellow]No modules selected. Use --all, a --profile, or pick specific flags.[/yellow]")
        console.print("Run [bold]python main.py --help[/bold] for options.")
        return results

    if tasks:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            job = progress.add_task("[cyan]Scanning...", total=len(tasks))
            gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
            progress.update(job, completed=len(tasks))

        for key, value in zip(tasks.keys(), gathered):
            results[key] = {"error": str(value)} if isinstance(value, Exception) else value

    # CVE needs tech results first
    if run_all or args.cve:
        results["cve"] = await scan_cve(args.target, tech_results=results.get("tech"), timeout=args.timeout)

    # Screenshots need subdomain results
    if run_all or args.screenshot:
        subs = results.get("subdomains") if isinstance(results.get("subdomains"), list) else None
        results["screenshots"] = await scan_screenshots(args.target, subdomains=subs, timeout=args.timeout)

    return results


def print_results(results):
    target  = results.get("target", "")
    profile = results.get("profile")
    tag     = f"  [dim](profile: {profile})[/dim]" if profile else ""
    console.print(f"\n[bold green]Scan complete:[/bold green] [cyan]{target}[/cyan]{tag}\n")

    if "subdomains" in results:
        data = results["subdomains"]
        t = Table(title="Subdomains", box=box.SIMPLE_HEAD, show_lines=False)
        t.add_column("Subdomain", style="cyan")
        t.add_column("IP", style="white")
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    t.add_row(item.get("subdomain", ""), item.get("ip", ""))
                else:
                    t.add_row(str(item), "")
        console.print(t)

    if "headers" in results:
        data = results["headers"]
        t = Table(title="HTTP Headers", box=box.SIMPLE_HEAD)
        t.add_column("Header", style="cyan", no_wrap=True)
        t.add_column("Value",  style="white", overflow="fold")
        t.add_column("Risk",   style="bold")
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, dict):
                    risk  = v.get("risk", "")
                    color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "INFO": "blue"}.get(risk, "white")
                    t.add_row(k, v.get("value", ""), f"[{color}]{risk}[/{color}]")
                else:
                    t.add_row(k, str(v), "")
        console.print(t)

    if "ports" in results:
        data = results["ports"]
        t = Table(title="Open Ports", box=box.SIMPLE_HEAD)
        t.add_column("Port",    style="cyan")
        t.add_column("Service", style="white")
        t.add_column("State",   style="green")
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    t.add_row(str(item.get("port", "")), item.get("service", ""), item.get("state", "open"))
        console.print(t)

    if "dns" in results:
        data = results["dns"]
        t = Table(title="DNS Records", box=box.SIMPLE_HEAD)
        t.add_column("Type",  style="cyan")
        t.add_column("Value", style="white", overflow="fold")
        if isinstance(data, dict):
            for rtype, records in data.items():
                for r in records:
                    t.add_row(rtype, str(r))
        console.print(t)

    if "whois" in results:
        data = results["whois"]
        t = Table(title="WHOIS", box=box.SIMPLE_HEAD)
        t.add_column("Field", style="cyan")
        t.add_column("Value", style="white", overflow="fold")
        if isinstance(data, dict):
            for k, v in data.items():
                t.add_row(k, str(v))
        console.print(t)

    if "tech" in results:
        data = results["tech"]
        t = Table(title="Technology Fingerprint", box=box.SIMPLE_HEAD)
        t.add_column("Category", style="cyan")
        t.add_column("Detected", style="white")
        if isinstance(data, dict):
            for k, v in data.items():
                t.add_row(k, ", ".join(v) if isinstance(v, list) else str(v))
        console.print(t)

    if "waf" in results:
        data = results["waf"]
        if isinstance(data, dict):
            waf_name = data.get("waf", "None detected")
            color    = "red" if data.get("detected") else "green"
            console.print(Panel(f"[{color}]{waf_name}[/{color}]", title="WAF Detection"))

    if "email" in results:
        data = results["email"]
        t = Table(title="Email Security", box=box.SIMPLE_HEAD)
        t.add_column("Check",  style="cyan")
        t.add_column("Status", style="bold")
        t.add_column("Value",  style="white", overflow="fold")
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, dict):
                    status = v.get("status", "")
                    color  = {"PASS": "green", "FAIL": "red", "WARN": "yellow"}.get(status, "white")
                    t.add_row(k, f"[{color}]{status}[/{color}]", v.get("value", ""))
        console.print(t)

    if "ssl" in results:
        data = results["ssl"]
        if isinstance(data, dict) and "error" not in data:
            t = Table(title="SSL/TLS Analysis", box=box.SIMPLE_HEAD)
            t.add_column("Field", style="cyan")
            t.add_column("Value", style="white", overflow="fold")
            t.add_row("Subject",  data.get("subject",  ""))
            t.add_row("Issuer",   data.get("issuer",   ""))
            t.add_row("Protocol", data.get("protocol", ""))
            t.add_row("Cipher",   data.get("cipher",   ""))
            t.add_row("Expires",  data.get("not_after",""))
            days = data.get("days_left")
            if days is not None:
                color = "red" if days < 30 else "green"
                t.add_row("Days Left", f"[{color}]{days}[/{color}]")
            console.print(t)
            risks = data.get("risks", [])
            if risks:
                rt = Table(title="SSL Risks", box=box.SIMPLE_HEAD)
                rt.add_column("Issue",    style="white", overflow="fold")
                rt.add_column("Severity", style="bold")
                for r in risks:
                    sev   = r.get("severity", "")
                    color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
                    rt.add_row(r.get("issue", ""), f"[{color}]{sev}[/{color}]")
                console.print(rt)

    if "cors" in results:
        data = results["cors"]
        if isinstance(data, dict):
            verdict = data.get("verdict", "UNKNOWN")
            color   = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "SAFE": "green"}.get(verdict, "white")
            console.print(Panel(f"[{color}]{verdict}[/{color}]  —  {data.get('issue_count', 0)} issue(s)", title="CORS Check"))
            for issue in data.get("issues", []):
                sev   = issue.get("severity", "")
                color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev, "white")
                console.print(f"  [{color}]▶[/{color}] {issue.get('issue','')}  [{color}]{sev}[/{color}]")

    if "cve" in results:
        data = results["cve"]
        if isinstance(data, dict) and data.get("findings"):
            overall = data.get("overall_severity", "NONE")
            color   = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "NONE": "green"}.get(overall, "white")
            console.print(Panel(
                f"[{color}]{overall}[/{color}]  —  {data.get('total_cves', 0)} CVE(s)  [dim](source: {data.get('source','')})[/dim]",
                title="CVE Lookup"
            ))
            for finding in data["findings"]:
                ft = Table(title=f"CVEs — {finding['tech']}", box=box.SIMPLE_HEAD)
                ft.add_column("CVE ID",      style="cyan")
                ft.add_column("Severity",    style="bold")
                ft.add_column("Description", style="white", overflow="fold")
                for cve in finding.get("cves", [])[:5]:
                    sev   = str(cve.get("severity", ""))
                    color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(sev.upper(), "white")
                    ft.add_row(cve.get("id",""), f"[{color}]{sev}[/{color}]", cve.get("description","")[:100])
                console.print(ft)

    if "robots" in results:
        data = results["robots"]
        if isinstance(data, dict):
            robots  = data.get("robots",  {})
            sitemap = data.get("sitemap", {})
            info = (
                f"robots.txt: {'[green]found[/green]' if robots.get('found') else '[dim]not found[/dim]'}  "
                f"sitemap.xml: {'[green]found[/green]' if sitemap.get('found') else '[dim]not found[/dim]'}  "
                f"URLs: {sitemap.get('url_count', 0)}"
            )
            console.print(Panel(info, title="Robots / Sitemap"))
            interesting = data.get("interesting", [])
            if interesting:
                it = Table(title=f"Interesting Paths ({len(interesting)})", box=box.SIMPLE_HEAD)
                it.add_column("Path", style="yellow", overflow="fold")
                for path in interesting[:30]:
                    it.add_row(path)
                console.print(it)
            disallowed = robots.get("disallowed", [])
            if disallowed:
                dt = Table(title=f"Disallowed Paths ({len(disallowed)})", box=box.SIMPLE_HEAD)
                dt.add_column("Path", style="white", overflow="fold")
                for path in disallowed[:20]:
                    dt.add_row(path)
                console.print(dt)

    if "screenshots" in results:
        data = results["screenshots"]
        if isinstance(data, dict):
            console.print(Panel(
                f"Captured: [green]{data.get('captured', 0)}[/green]  Output: [cyan]{data.get('output_dir', '')}[/cyan]",
                title="Screenshots"
            ))


async def main():
    console.print(BANNER)
    args = parse_args()

    if args.list_profiles:
        list_profiles()
        return
    if args.delete_profile:
        delete_profile(args.delete_profile)
        return
    if not args.target:
        console.print("[red]Error:[/red] Please provide a target domain.")
        console.print("Usage: [bold]python main.py <target> [options][/bold]")
        return
    if args.save_profile:
        save_profile(args.save_profile, args, description=args.desc)
        return

    if args.profile:
        profile = get_profile(args.profile)
        if not profile:
            console.print(f"[red]Unknown profile '[cyan]{args.profile}[/cyan]'.[/red]  "
                          f"Run [bold]python main.py --list-profiles[/bold] to see available profiles.")
            return
        args = apply_profile(profile, args)
        args._active_profile = args.profile
        console.print(Panel(
            f"[bold cyan]{args.profile}[/bold cyan]  —  {profile['description']}\n"
            f"[dim]Timeout: {args.timeout}s   Threads: {args.threads}[/dim]",
            title="Active Profile", border_style="cyan"
        ))
    else:
        args._active_profile = None

    console.print(
        f"[bold]Target:[/bold] [cyan]{args.target}[/cyan]  "
        f"[bold]Timeout:[/bold] {args.timeout}s  "
        f"[bold]Threads:[/bold] {args.threads}\n"
    )

    results = await run_scans(args)
    print_results(results)

    if args.output:
        path = generate_report(results, fmt=args.output)
        console.print(f"\n[bold green]Report saved:[/bold green] {path}")


if __name__ == "__main__":
    asyncio.run(main())
