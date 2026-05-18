# Changelog

All notable changes to Ne0 are documented here.

---

## [1.1.0] - 2026-05-18

### Added
- **Scan Profiles** — run pre-configured scans with a single flag
  - Built-in profiles: `quick`, `deep`, `stealth`, `web`, `network`
  - `--profile NAME` — activate a named profile
  - `--list-profiles` — show all built-in and custom profiles
  - `--save-profile NAME` — save current flags as a custom profile
  - `--delete-profile NAME` — remove a custom profile
  - `--desc TEXT` — add a description when saving a profile
  - Custom profiles stored at `~/.ne0/profiles.json`
- Profile name shown in scan output and saved reports
- New `utils/profiles.py` module

### Changed
- `main.py` updated to handle profile arguments before scan execution
- README updated with full profiles documentation and usage table
- Added `CHANGELOG.md`

---

## [1.0.0] - Initial Release

### Added
- Subdomain enumeration
- HTTP header analysis with risk scoring
- Port scanning
- DNS record enumeration
- WHOIS lookup
- Technology fingerprinting
- WAF detection
- Email security checks (SPF / DKIM / DMARC)
- JSON and HTML report generation
- Async multi-threaded scanning engine
- Rich terminal output
