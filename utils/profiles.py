"""
Ne0 - Scan Profiles
Built-in profiles: quick, deep, stealth, web, network
Custom profiles: saved/loaded from ~/.ne0/profiles.json
"""

import json
import os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

PROFILES_DIR = Path.home() / ".ne0"
PROFILES_FILE = PROFILES_DIR / "profiles.json"

# ── Built-in profiles ──────────────────────────────────────────────────────────
BUILTIN_PROFILES = {
    "quick": {
        "description": "Fast recon — DNS, headers, WAF only",
        "modules": {
            "subdomains": False,
            "headers":    True,
            "ports":      False,
            "dns":        True,
            "whois":      False,
            "tech":       True,
            "waf":        True,
            "email":      False,
        },
        "timeout": 5,
        "threads": 50,
        "output":  None,
    },
    "deep": {
        "description": "Full recon — all modules enabled",
        "modules": {
            "subdomains": True,
            "headers":    True,
            "ports":      True,
            "dns":        True,
            "whois":      True,
            "tech":       True,
            "waf":        True,
            "email":      True,
        },
        "timeout": 10,
        "threads": 100,
        "output":  "html",
    },
    "stealth": {
        "description": "Low-noise recon — slow, minimal requests",
        "modules": {
            "subdomains": True,
            "headers":    True,
            "ports":      False,
            "dns":        True,
            "whois":      True,
            "tech":       False,
            "waf":        True,
            "email":      False,
        },
        "timeout": 15,
        "threads": 5,
        "output":  "json",
    },
    "web": {
        "description": "Web-focused — headers, tech, WAF, email security",
        "modules": {
            "subdomains": False,
            "headers":    True,
            "ports":      False,
            "dns":        False,
            "whois":      False,
            "tech":       True,
            "waf":        True,
            "email":      True,
        },
        "timeout": 5,
        "threads": 30,
        "output":  None,
    },
    "network": {
        "description": "Network-focused — subdomains, ports, DNS",
        "modules": {
            "subdomains": True,
            "headers":    False,
            "ports":      True,
            "dns":        True,
            "whois":      True,
            "tech":       False,
            "waf":        False,
            "email":      False,
        },
        "timeout": 8,
        "threads": 80,
        "output":  None,
    },
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _load_custom_profiles() -> dict:
    if PROFILES_FILE.exists():
        try:
            with open(PROFILES_FILE) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_custom_profiles(profiles: dict):
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    with open(PROFILES_FILE, "w") as f:
        json.dump(profiles, f, indent=2)


def get_profile(name: str) -> dict | None:
    """Return a profile dict by name (built-in first, then custom)."""
    if name in BUILTIN_PROFILES:
        return BUILTIN_PROFILES[name]
    custom = _load_custom_profiles()
    return custom.get(name)


def list_profiles():
    """Print a Rich table of all available profiles."""
    custom = _load_custom_profiles()

    t = Table(title="Available Scan Profiles", box=box.SIMPLE_HEAD, show_lines=True)
    t.add_column("Name",        style="bold cyan",  no_wrap=True)
    t.add_column("Type",        style="dim")
    t.add_column("Description", style="white")
    t.add_column("Modules",     style="green")
    t.add_column("Timeout", style="yellow")
    t.add_column("Threads", style="yellow")

    for name, cfg in BUILTIN_PROFILES.items():
        mods = ", ".join(k for k, v in cfg["modules"].items() if v)
        t.add_row(name, "built-in", cfg["description"], mods,
                  str(cfg["timeout"]) + "s", str(cfg["threads"]))

    for name, cfg in custom.items():
        mods = ", ".join(k for k, v in cfg.get("modules", {}).items() if v)
        t.add_row(name, "[magenta]custom[/magenta]",
                  cfg.get("description", ""), mods,
                  str(cfg.get("timeout", 5)) + "s",
                  str(cfg.get("threads", 50)))

    console.print(t)


def save_profile(name: str, args, description: str = ""):
    """Save current CLI args as a named custom profile."""
    if name in BUILTIN_PROFILES:
        console.print(f"[red]Cannot overwrite built-in profile '{name}'.[/red]")
        return

    custom = _load_custom_profiles()
    custom[name] = {
        "description": description or f"Custom profile '{name}'",
        "modules": {
            "subdomains": args.subdomains,
            "headers":    args.headers,
            "ports":      args.ports,
            "dns":        args.dns,
            "whois":      args.whois,
            "tech":       args.tech,
            "waf":        args.waf,
            "email":      args.email,
        },
        "timeout": args.timeout,
        "threads": args.threads,
        "output":  args.output,
    }
    _save_custom_profiles(custom)
    console.print(f"[bold green]Profile '[cyan]{name}[/cyan]' saved![/bold green] "
                  f"({PROFILES_FILE})")


def delete_profile(name: str):
    """Delete a custom profile by name."""
    if name in BUILTIN_PROFILES:
        console.print(f"[red]Cannot delete built-in profile '{name}'.[/red]")
        return
    custom = _load_custom_profiles()
    if name not in custom:
        console.print(f"[red]Profile '{name}' not found.[/red]")
        return
    del custom[name]
    _save_custom_profiles(custom)
    console.print(f"[bold green]Profile '[cyan]{name}[/cyan]' deleted.[/bold green]")


def apply_profile(profile: dict, args):
    """
    Merge profile settings into a parsed args namespace.
    CLI flags always win over profile defaults.
    """
    mods = profile.get("modules", {})

    # Only apply profile module if user didn't explicitly pass any module flag
    any_module_flag = any([
        args.subdomains, args.headers, args.ports, args.dns,
        args.whois, args.tech, args.waf, args.email, args.all
    ])

    if not any_module_flag:
        for mod, enabled in mods.items():
            setattr(args, mod, enabled)

    # Apply timeout / threads only if user left them at defaults
    if args.timeout == 5:
        args.timeout = profile.get("timeout", 5)
    if args.threads == 50:
        args.threads = profile.get("threads", 50)

    # Apply output only if user didn't specify one
    if args.output is None and profile.get("output"):
        args.output = profile["output"]

    return args
