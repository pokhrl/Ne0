# 🦉Ne0

![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A lightweight Python tool for **mapping basic web attack surfaces**.  
Designed for security enthusiasts, pentesters, and developers to **discover subdomains, HTTP headers, open ports, and TLS info** in a safe and modular way.

---

## Features

- Discover common subdomains
- Scan HTTP headers
- Optional port scanning (common TCP ports)
- TLS/SSL certificate information
- DNS intelligence & WHOIS lookup
- Technology fingerprinting
- WAF detection
- Email security checks (SPF / DKIM / DMARC)
- **Scan Profiles** — built-in and custom named profiles
- JSON / HTML report generation
- Modular, easy-to-extend architecture

---

## Requirements

- Python 3.10 or higher
- Dependencies:
  ```bash
  pip install -r requirements.txt
  ```

---

## Install

```bash
git clone https://github.com/pokhrl/Ne0.git
cd Ne0
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic scan with individual flags
python main.py example.com --dns --headers --waf

# Run all modules
python main.py example.com --all

# Run all modules and save an HTML report
python main.py example.com --all --output html
```

---

## Scan Profiles

Profiles let you run pre-configured scans without typing flags every time.

### Built-in Profiles

| Profile   | Description                                    |
|-----------|------------------------------------------------|
| `quick`   | Fast recon — DNS, headers, WAF, tech           |
| `deep`    | Full recon — all modules, saves HTML report    |
| `stealth` | Low-noise — slow, minimal footprint            |
| `web`     | Web-focused — headers, tech, WAF, email        |
| `network` | Network-focused — subdomains, ports, DNS       |

```bash
python main.py example.com --profile quick
python main.py example.com --profile deep
python main.py example.com --profile stealth
python main.py example.com --profile web
python main.py example.com --profile network
```

### List All Profiles

```bash
python main.py --list-profiles
```

### Save a Custom Profile

Run with any flags and save them as a named profile:

```bash
python main.py example.com --dns --waf --tech --timeout 8 --save-profile myprofile --desc "My favourite recon combo"
```

Next time just use:

```bash
python main.py example.com --profile myprofile
```

Custom profiles are stored at `~/.ne0/profiles.json`.

### Delete a Custom Profile

```bash
python main.py --delete-profile myprofile
```

> **Note:** Built-in profiles cannot be deleted or overwritten.

---

## Output

```bash
# Save as JSON
python main.py example.com --profile deep --output json

# Save as HTML
python main.py example.com --all --output html
```

---

## Options

```
positional arguments:
  target                Target domain (e.g. example.com)

profiles:
  --profile NAME        Run a named scan profile
  --list-profiles       List all available profiles and exit
  --save-profile NAME   Save current module flags as a custom profile
  --desc TEXT           Description for --save-profile
  --delete-profile NAME Delete a custom profile

modules:
  --subdomains          Enumerate subdomains
  --headers             Scan HTTP headers
  --ports               Scan common ports
  --dns                 Enumerate DNS records
  --whois               WHOIS lookup
  --tech                Technology fingerprinting
  --waf                 WAF detection
  --email               Email security (SPF/DKIM/DMARC)
  --all                 Run all modules

output:
  --output {json,html}  Save report
  --timeout SECONDS     Request timeout (default: 5)
  --threads N           Max concurrent tasks (default: 50)
```

---

## Disclaimer

Ne0 is intended for **authorized security testing only**.  
Do not use against systems you do not own or have explicit permission to test.
