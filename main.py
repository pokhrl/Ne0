import argparse
import asyncio
import json
import datetime

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from scanner.subdomain_scan import scan_subdomains
from scanner.header_scan import scan_headers
from scanner.port_scan import scan_ports
from scanner.dns_scan import scan_dns
from scanner.whois_scan import scan_whois
from scanner.tech_scan import scan_tech
from scanner.waf_scan import scan_waf
from scanner.email_sec_scan import scan_email_security
from utils.report import generate_report
from utils.profiles import (
    get_profile, list_profiles,
    save_profile, delete_profile, apply_profile,
    BUILTIN_PROFILES
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

    # ── Target ────────────────────────────────────────────────────────────────
    parser.add_argument("target", nargs="?", help="Target domain (e.g. example.com)")

    # ── Profile controls ──────────────────────────────────────────────────────
    profile_group = parser.add_argument_group("Profiles")
    profile_group.add_argument(
        "--profile",
        metavar="NAME",
        help="Run a named scan profile (quick / deep / stealth / web / network / custom)"
    )
    profile_group.add_argument(
        "--list-profiles",
        action="store_true",
        help="List all available profiles and exit"
    )
    profile_group.add_argument(
        "--save-profile",
        metavar="NAME",
        help="Save current module flags as a new custom profile"
    )
    profile_group.add_argument(
        "--desc",
        metavar="TEXT",
        default="",
        help="Description for --save-profile"
    )
    profile_group.add_argument(
        "--delete-profile",
        metavar="NAME",
        help="Delete a custom profile by name"
    )

    # ── Scan modules ──────────────────────────────────────────────────────────
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains")
    parser.add_argument("--headers",    action="store_true", help="Scan HTTP headers")
    parser.add_argument("--ports",      action="store_true", help="Scan common ports")
    parser.add_argument("--dns",        action="store_true", help="Enumerate DNS records")
    parser.add_argument("--whois",      action="store_true", help="WHOIS lookup")
    parser.add_argument("--tech",       action="store_true", help="Technology fingerprinting")
    parser.add_argument("--waf",        action="store_true", help="WAF detection")
    parser.add_argument("--email",      action="store_true", help="Email security (SPF/DKIM/DMARC)")
    parser.add_argument("--all",        action="store_true", help="Run all modules")

    # ── Output / tuning ───────────────────────────────────────────────────────
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
        tasks["headers"] = scan_headers(args.target, args.timeout)
    if run_all or args.ports:
        tasks["ports"] = scan_ports(args.target, args.timeout, args.threads)
    if run_all or args.dns:
        tasks["dns"] = scan_dns(args.target)
    if run_all or args.whois:
        tasks["whois"] = scan_whois(args.target)
    if run_all or args.tech:
        tasks["tech"] = scan_tech(args.target, args.timeout)
    if run_all or args.waf:
        tasks["waf"] = scan_waf(args.target, args.timeout)
    if run_all or args.email:
        tasks["email"] = scan_email_security(args.target)

    if not tasks:
        console.print("[yellow]No modules selected. Use --all, a --profile, or pick specific flags.[/yellow]")
        console.print("Run [bold]python main.py --help[/bold] for options.")
        return results

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        job = progress.add_task("[cyan]Scanning...", total=len(tasks))
        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        progress.update(job, completed=len(tasks))

    for key, value in zip(tasks.keys(), gathered):
        if isinstance(value, Exception):
            results[key] = {"error": str(value)}
        else:
            results[key] = value

    return results


def print_results(results):
    target = results.get("target", "")
    profile = results.get("profile")
    profile_tag = f"  [dim](profile: {profile})[/dim]" if profile else ""
    console.print(f"\n[bold green]Scan complete:[/bold green] [cyan]{target}[/cyan]{profile_tag}\n")

    # Subdomains
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

    # Headers
    if "headers" in results:
        data = results["headers"]
        t = Table(title="HTTP Headers", box=box.SIMPLE_HEAD)
        t.add_column("Header", style="cyan", no_wrap=True)
        t.add_column("Value", style="white", overflow="fold")
        t.add_column("Risk", style="bold")
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, dict):
                    risk  = v.get("risk", "")
                    color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "INFO": "blue"}.get(risk, "white")
                    t.add_row(k, v.get("value", ""), f"[{color}]{risk}[/{color}]")
                else:
                    t.add_row(k, str(v), "")
        console.print(t)

    # Ports
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

    # DNS
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

    # WHOIS
    if "whois" in results:
        data = results["whois"]
        t = Table(title="WHOIS", box=box.SIMPLE_HEAD)
        t.add_column("Field", style="cyan")
        t.add_column("Value", style="white", overflow="fold")
        if isinstance(data, dict):
            for k, v in data.items():
                t.add_row(k, str(v))
        console.print(t)

    # Tech fingerprint
    if "tech" in results:
        data = results["tech"]
        t = Table(title="Technology Fingerprint", box=box.SIMPLE_HEAD)
        t.add_column("Category", style="cyan")
        t.add_column("Detected", style="white")
        if isinstance(data, dict):
            for k, v in data.items():
                t.add_row(k, ", ".join(v) if isinstance(v, list) else str(v))
        console.print(t)

    # WAF
    if "waf" in results:
        data = results["waf"]
        if isinstance(data, dict):
            waf_name = data.get("waf", "None detected")
            color    = "red" if data.get("detected") else "green"
            console.print(Panel(f"[{color}]{waf_name}[/{color}]", title="WAF Detection"))

    # Email security
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


async def main():
    console.print(BANNER)
    args = parse_args()

    # ── Profile management commands (no target needed) ────────────────────────
    if args.list_profiles:
        list_profiles()
        return

    if args.delete_profile:
        delete_profile(args.delete_profile)
        return

    # ── Target is required from here on ──────────────────────────────────────
    if not args.target:
        console.print("[red]Error:[/red] Please provide a target domain.")
        console.print("Usage: [bold]python main.py <target> [options][/bold]")
        return

    # ── Save profile (uses current flags) ─────────────────────────────────────
    if args.save_profile:
        save_profile(args.save_profile, args, description=args.desc)
        return

    # ── Apply profile if requested ────────────────────────────────────────────
    if args.profile:
        profile = get_profile(args.profile)
        if not profile:
            console.print(f"[red]Unknown profile '[cyan]{args.profile}[/cyan]'.[/red]  "
                          f"Run [bold]python main.py --list-profiles[/bold] to see available profiles.")
            return
        args = apply_profile(profile, args)
        args._active_profile = args.profile
        console.print(
            Panel(
                f"[bold cyan]{args.profile}[/bold cyan]  —  {profile['description']}\n"
                f"[dim]Timeout: {args.timeout}s   Threads: {args.threads}[/dim]",
                title="Active Profile",
                border_style="cyan"
            )
        )
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
