"""
Ne0 - SSL/TLS Deep Scanner
Checks cipher suites, certificate expiry, weak configs, and common misconfigs.
"""

import asyncio
import ssl
import socket
import datetime


WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon"
]

WEAK_PROTOCOLS = [
    "SSLv2", "SSLv3", "TLSv1", "TLSv1.1"
]


def _get_cert_info(hostname: str, port: int = 443, timeout: int = 5) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert      = ssock.getpeercert()
                cipher    = ssock.cipher()
                version   = ssock.version()
                return {"cert": cert, "cipher": cipher, "version": version}
    except Exception as e:
        return {"error": str(e)}


def _check_weak_protocols(hostname: str, timeout: int) -> list:
    found = []
    weak_map = {
        "TLSv1":   ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1")   else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
    }
    for name, version in weak_map.items():
        if version is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    found.append(name)
        except Exception:
            pass
    return found


def _days_until_expiry(cert: dict) -> int | None:
    try:
        expiry_str = cert.get("notAfter", "")
        expiry     = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        return (expiry - datetime.datetime.utcnow()).days
    except Exception:
        return None


async def scan_ssl(target: str, timeout: int = 5) -> dict:
    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _get_cert_info, target, 443, timeout)

    if "error" in result:
        return {"error": result["error"]}

    cert    = result["cert"]
    cipher  = result["cipher"]   # (name, protocol, bits)
    version = result["version"]

    # ── Certificate fields ────────────────────────────────────────────────────
    subject  = dict(x[0] for x in cert.get("subject",  []))
    issuer   = dict(x[0] for x in cert.get("issuer",   []))
    san      = [v for _, v in cert.get("subjectAltName", [])]
    days_left = _days_until_expiry(cert)

    # ── Risk flags ────────────────────────────────────────────────────────────
    risks = []
    if days_left is not None and days_left < 30:
        risks.append({"issue": "Certificate expiring soon", "days_left": days_left, "severity": "HIGH"})
    if days_left is not None and days_left < 0:
        risks.append({"issue": "Certificate EXPIRED", "days_left": days_left, "severity": "CRITICAL"})

    cipher_name = cipher[0] if cipher else ""
    for weak in WEAK_CIPHERS:
        if weak in cipher_name.upper():
            risks.append({"issue": f"Weak cipher in use: {cipher_name}", "severity": "HIGH"})
            break

    if version in WEAK_PROTOCOLS:
        risks.append({"issue": f"Weak protocol in use: {version}", "severity": "HIGH"})

    # ── Weak protocol support check (non-blocking best effort) ────────────────
    weak_proto_supported = await loop.run_in_executor(None, _check_weak_protocols, target, timeout)
    for proto in weak_proto_supported:
        risks.append({"issue": f"Weak protocol supported by server: {proto}", "severity": "MEDIUM"})

    # ── Self-signed check ─────────────────────────────────────────────────────
    if subject == issuer:
        risks.append({"issue": "Self-signed certificate", "severity": "MEDIUM"})

    return {
        "subject":      subject.get("commonName", ""),
        "issuer":       issuer.get("organizationName", ""),
        "san":          san,
        "not_before":   cert.get("notBefore", ""),
        "not_after":    cert.get("notAfter", ""),
        "days_left":    days_left,
        "protocol":     version,
        "cipher":       cipher_name,
        "cipher_bits":  cipher[2] if cipher else None,
        "risks":        risks,
        "risk_count":   len(risks),
    }
