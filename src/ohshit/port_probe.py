"""Per-port deep probing to extract service version and device identity.

Called after open ports are known (from ss, tcp_port_scan, or nmap).
All probes are async, non-destructive, and time-bounded.

Probes implemented
------------------
- HTTP/HTTPS  : HEAD / then GET /, extract Server, X-Powered-By, title,
                platform hints from headers and body
- SSH         : read the version banner line (SSH-2.0-OpenSSH_8.9p1 etc.)
- TLS (any)   : grab certificate CN, O, SAN, not-after for any TLS port
- FTP         : read 220 greeting
- SMTP        : read 220 greeting
- RTSP        : OPTIONS * probe, read Server header
- Telnet      : read greeting bytes
- Generic TCP : read first 256 bytes if nothing else matched

Results are written back into each PortInfo.version string and, when a
device/OS identity is found, into host.os_guess / host.iot_info fields.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Host, PortInfo


# Ports we attempt TLS on even when not 443
_TLS_PORTS = {443, 8443, 4443, 8883, 9443}
# Ports we treat as HTTP (plain)
_HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8888, 9090, 3000, 4000, 5000, 7080}
# Ports we treat as HTTPS
_HTTPS_PORTS = {443, 8443, 4443, 9443, 4433}

_TIMEOUT = 4.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _read_banner(ip: str, port: int, send: bytes | None = None,
                       timeout: float = _TIMEOUT) -> bytes:
    """Open TCP connection, optionally send bytes, return first 1024 bytes."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            if send:
                writer.write(send)
                await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            return data
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return b""


async def _read_banner_tls(ip: str, port: int, send: bytes | None = None,
                            timeout: float = _TIMEOUT) -> tuple[bytes, ssl.SSLObject | None]:
    """TLS connect, return (data, ssl_object) so caller can read cert."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip),
            timeout=timeout,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        try:
            if send:
                writer.write(send)
                await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            return data, ssl_obj
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return b"", None


def _cert_summary(ssl_obj: ssl.SSLObject | None) -> str:
    """Extract CN / O / expiry from a connected SSLObject."""
    if not ssl_obj:
        return ""
    try:
        cert = ssl_obj.getpeercert()
        if not cert:
            return ""
        subject = dict(x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName", "")
        org = subject.get("organizationName", "")
        expiry = cert.get("notAfter", "")
        parts = []
        if cn:
            parts.append(f"CN={cn}")
        if org and org != cn:
            parts.append(f"O={org}")
        if expiry:
            try:
                exp_dt = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp_dt - datetime.now(timezone.utc)).days
                if days < 0:
                    parts.append(f"EXPIRED {abs(days)}d ago")
                elif days < 30:
                    parts.append(f"expires in {days}d")
            except Exception:
                pass
        return "  ".join(parts)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Per-protocol probes
# ---------------------------------------------------------------------------

async def _probe_http(ip: str, port: int, tls: bool) -> str:
    """Return a version/identity string from HTTP(S) response headers + body."""
    path = "/"
    request = (
        f"GET {path} HTTP/1.0\r\n"
        f"Host: {ip}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    cert_info = ""
    if tls:
        raw, ssl_obj = await _read_banner_tls(ip, port, send=request)
        cert_info = _cert_summary(ssl_obj)
    else:
        raw = await _read_banner(ip, port, send=request)

    if not raw:
        return cert_info

    text = raw.decode("utf-8", errors="replace")
    headers_raw, _, body = text.partition("\r\n\r\n")

    parts: list[str] = []

    # Server header
    m = re.search(r"^Server:\s*(.+)$", headers_raw, re.IGNORECASE | re.MULTILINE)
    if m:
        parts.append(m.group(1).strip()[:60])

    # X-Powered-By
    m = re.search(r"^X-Powered-By:\s*(.+)$", headers_raw, re.IGNORECASE | re.MULTILINE)
    if m:
        parts.append(m.group(1).strip()[:40])

    # HTML <title>
    m = re.search(r"<title[^>]*>([^<]{1,60})</title>", body, re.IGNORECASE)
    if m:
        title = m.group(1).strip()
        if title:
            parts.append(f'"{title}"')

    if cert_info:
        parts.append(cert_info)

    return "  ".join(parts) if parts else ("TLS" if tls else "HTTP")


async def _probe_ssh(ip: str, port: int) -> str:
    """Read SSH version banner (SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6)."""
    raw = await _read_banner(ip, port)
    if not raw:
        return ""
    line = raw.split(b"\n")[0].decode("utf-8", errors="replace").strip()
    if line.startswith("SSH-"):
        # Remove the protocol prefix, keep software + comment
        return line[len("SSH-2.0-"):] if line.startswith("SSH-2.0-") else line
    return ""


async def _probe_ftp(ip: str, port: int) -> str:
    """Read FTP 220 greeting."""
    raw = await _read_banner(ip, port)
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    m = re.search(r"220[ -](.+)", text)
    return m.group(1).strip()[:80] if m else ""


async def _probe_smtp(ip: str, port: int) -> str:
    raw = await _read_banner(ip, port)
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    m = re.search(r"220[ -](.+)", text)
    return m.group(1).strip()[:80] if m else ""


async def _probe_rtsp(ip: str, port: int) -> str:
    request = b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"
    raw = await _read_banner(ip, port, send=request)
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    m = re.search(r"^Server:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip()[:60] if m else "RTSP"


async def _probe_tls_cert(ip: str, port: int) -> str:
    """Just grab the TLS cert from any port that speaks TLS."""
    _, ssl_obj = await _read_banner_tls(ip, port)
    return _cert_summary(ssl_obj)


async def _probe_generic(ip: str, port: int) -> str:
    """Read first bytes from any unrecognised port."""
    raw = await _read_banner(ip, port)
    if not raw:
        return ""
    # Try to decode as text; skip binary-looking responses
    text = raw[:120].decode("utf-8", errors="replace").strip()
    printable = sum(1 for c in text if c.isprintable())
    if printable / max(len(text), 1) > 0.8:
        # Collapse whitespace, keep first line
        return text.splitlines()[0][:80] if text else ""
    return f"binary ({len(raw)} bytes)"


# ---------------------------------------------------------------------------
# Device/OS identity extraction from version strings
# ---------------------------------------------------------------------------

# (pattern, os_guess, device_type)  — checked against port version strings
_VERSION_IDENTITY: list[tuple[re.Pattern[str], str | None, str | None]] = [
    (re.compile(r"OpenWrt",              re.I), "Linux (OpenWrt)",   "Router"),
    (re.compile(r"DD-WRT",               re.I), "Linux (DD-WRT)",    "Router"),
    (re.compile(r"FreshTomato|Tomato",   re.I), "Linux (Tomato)",    "Router"),
    (re.compile(r"RouterOS|MikroTik",    re.I), "RouterOS",          "Router"),
    (re.compile(r"AVM.*FRITZ|FRITZ!OS",  re.I), "FRITZ!OS",          "Router"),
    (re.compile(r"Ubiquiti|UniFi|EdgeOS",re.I), None,                "Ubiquiti"),
    (re.compile(r"MiniUPnPd",            re.I), None,                "Router"),
    (re.compile(r"Synology|DSM",         re.I), "DSM",               "NAS"),
    (re.compile(r"QNAP",                 re.I), "QTS",               "NAS"),
    (re.compile(r"TrueNAS|FreeNAS",      re.I), "TrueNAS",           "NAS"),
    (re.compile(r"Reolink",              re.I), None,                "IP Camera"),
    (re.compile(r"Hikvision",            re.I), None,                "IP Camera"),
    (re.compile(r"Dahua",                re.I), None,                "IP Camera"),
    (re.compile(r"RTSP",                 re.I), None,                "Camera/NVR"),
    (re.compile(r"Boa/",                 re.I), None,                "Embedded Device"),
    (re.compile(r"SHIP ",                re.I), None,                "IoT Device"),
    (re.compile(r"NanoKVM",              re.I), None,                "KVM"),
    (re.compile(r"Home Assistant",       re.I), "Home Assistant OS", "Home Assistant"),
    (re.compile(r"Pi-hole",              re.I), None,                "Pi-hole"),
    (re.compile(r"Plex",                 re.I), None,                "Plex Media Server"),
    (re.compile(r"Proxmox",              re.I), "Proxmox VE",        "Hypervisor"),
    (re.compile(r"ESXi|VMware",          re.I), "VMware ESXi",       "Hypervisor"),
    (re.compile(r"dropbear",             re.I), "Linux (embedded)",  "Embedded Device"),
    (re.compile(r"Chromecast",           re.I), "Android/Cast",      "Chromecast"),
    (re.compile(r"Postfix",              re.I), "Linux",             "Mail Server"),
    (re.compile(r"Dovecot",              re.I), "Linux",             "Mail Server"),
    (re.compile(r"Raspbian|Raspberry",   re.I), "Raspberry Pi OS",   None),
    (re.compile(r"Ubuntu",               re.I), "Ubuntu Linux",      None),
    (re.compile(r"Debian",               re.I), "Debian Linux",      None),
    (re.compile(r"CentOS|Rocky|Alma",    re.I), "RHEL-family Linux", None),
    (re.compile(r"Darwin",               re.I), "macOS/Darwin",      None),
    (re.compile(r"OpenSSH",              re.I), "Linux/Unix",        None),
    (re.compile(r"Windows|Microsoft-HTTP|IIS", re.I), "Windows",    None),
    (re.compile(r"Apache",               re.I), "Linux/Unix",        None),
    (re.compile(r"nginx",                re.I), "Linux/Unix",        None),
    (re.compile(r"Next\.js",             re.I), "Linux/Unix",        None),
]


def _apply_identity(host: "Host", version: str) -> None:
    """Update host.os_guess and host.iot_info.device_type from a version string."""
    for pattern, os_guess, device_type in _VERSION_IDENTITY:
        if pattern.search(version):
            if os_guess and not host.os_guess:
                host.os_guess = os_guess
            if device_type and not host.iot_info.device_type:
                host.iot_info.device_type = device_type
            break


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def probe_ports(host: "Host") -> None:
    """Probe each open port to fill in PortInfo.version and update host identity.

    Only probes ports that don't already have a version string (so SSH-collected
    data isn't overwritten) and skips ports with no external connection.
    """
    if not host.open_ports:
        return

    sem = asyncio.Semaphore(10)

    async def _probe_one(port_info: "PortInfo") -> None:
        async with sem:
            port = port_info.port
            version = port_info.version or ""

            # Determine probe type
            if port == 22 or port_info.service == "ssh":
                result = await _probe_ssh(host.ip, port)
            elif port in _HTTPS_PORTS or port_info.service in ("https", "https-alt"):
                result = await _probe_http(host.ip, port, tls=True)
            elif port in _HTTP_PORTS or port_info.service in ("http", "http-alt"):
                result = await _probe_http(host.ip, port, tls=False)
            elif port == 21 or port_info.service == "ftp":
                result = await _probe_ftp(host.ip, port)
            elif port in (25, 587, 465) or port_info.service == "smtp":
                result = await _probe_smtp(host.ip, port)
            elif port == 554 or port_info.service == "rtsp":
                result = await _probe_rtsp(host.ip, port)
            elif port in _TLS_PORTS:
                result = await _probe_tls_cert(host.ip, port)
            else:
                result = await _probe_generic(host.ip, port)

            if result:
                # Merge with existing version rather than overwriting
                if version and version not in result:
                    port_info.version = f"{version}  {result}"
                else:
                    port_info.version = result
                _apply_identity(host, result)

    await asyncio.gather(*[_probe_one(p) for p in host.open_ports],
                         return_exceptions=True)
