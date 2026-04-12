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
# ESPHome native API probe (port 6053)
# ---------------------------------------------------------------------------

def _varint_encode(v: int) -> bytes:
    out = bytearray()
    while v > 0x7F:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _varint_decode(data: bytes, offset: int) -> tuple[int, int]:
    """Return (value, new_offset)."""
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, offset


def _make_api_packet(msg_type: int, payload: bytes = b"") -> bytes:
    return b"\x00" + _varint_encode(len(payload)) + _varint_encode(msg_type) + payload


def _parse_api_packet(data: bytes) -> tuple[int, bytes] | None:
    """Return (msg_type, payload) or None if data is incomplete/invalid."""
    if not data or data[0] != 0x00:
        return None
    try:
        length, off = _varint_decode(data, 1)
        msg_type, off = _varint_decode(data, off)
        payload = data[off:off + length]
        return msg_type, payload
    except Exception:
        return None


def _parse_string_field(payload: bytes, field_number: int) -> str | None:
    """Extract a single string field from a minimal protobuf payload."""
    # Wire type 2 (length-delimited) tag = (field_number << 3) | 2
    tag = (field_number << 3) | 2
    i = 0
    while i < len(payload):
        try:
            t, i = _varint_decode(payload, i)
            wtype = t & 0x07
            fnum = t >> 3
            if wtype == 2:
                length, i = _varint_decode(payload, i)
                value = payload[i:i + length]
                i += length
                if fnum == field_number:
                    return value.decode("utf-8", errors="replace")
            elif wtype == 0:
                _, i = _varint_decode(payload, i)
            elif wtype == 5:
                i += 4
            elif wtype == 1:
                i += 8
            else:
                break  # unknown wire type, bail
        except Exception:
            break
    return None


def _parse_all_string_fields(payload: bytes) -> dict[int, str]:
    """Extract all string fields from a protobuf payload as {field_number: value}."""
    result: dict[int, str] = {}
    i = 0
    while i < len(payload):
        try:
            t, i = _varint_decode(payload, i)
            wtype = t & 0x07
            fnum = t >> 3
            if wtype == 2:
                length, i = _varint_decode(payload, i)
                value = payload[i:i + length]
                i += length
                try:
                    text = value.decode("utf-8", errors="replace")
                    if text.isprintable() or all(c.isprintable() or c in " \t" for c in text):
                        result[fnum] = text
                except Exception:
                    pass
            elif wtype == 0:
                _, i = _varint_decode(payload, i)
            elif wtype == 5:
                i += 4
            elif wtype == 1:
                i += 8
            else:
                break
        except Exception:
            break
    return result


async def _probe_esphome_api(ip: str, port: int = 6053) -> dict[str, str]:
    """Query ESPHome native API for device info without authentication.

    Sends HelloRequest then DeviceInfoRequest; parses DeviceInfoResponse.
    Returns a dict with keys: name, friendly_name, model, manufacturer,
    esphome_version, compilation_time, project_name, project_version,
    suggested_area, mac_address.
    """
    # HelloRequest (msg type 1): client_info field 1 = "ohshit-probe"
    client_info = b"ohshit-probe"
    hello_payload = b"\x0a" + _varint_encode(len(client_info)) + client_info
    hello_pkt = _make_api_packet(1, hello_payload)
    # DeviceInfoRequest (msg type 9): empty payload
    devinfo_pkt = _make_api_packet(9)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=_TIMEOUT
        )
        try:
            writer.write(hello_pkt)
            await writer.drain()
            # Read HelloResponse
            hello_resp = await asyncio.wait_for(reader.read(256), timeout=_TIMEOUT)
            if not hello_resp or hello_resp[0] == 0x01:
                # 0x01 = Noise encryption required — can't probe without key
                return {}
            # Send DeviceInfoRequest
            writer.write(devinfo_pkt)
            await writer.drain()
            # Read DeviceInfoResponse (may come in chunks)
            devinfo_resp = await asyncio.wait_for(reader.read(1024), timeout=_TIMEOUT)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return {}

    parsed = _parse_api_packet(devinfo_resp)
    if not parsed or parsed[0] != 10:  # 10 = DeviceInfoResponse
        return {}

    # Field numbers from ESPHome api.proto DeviceInfoResponse:
    # 2=name, 3=mac_address, 4=esphome_version, 5=compilation_time,
    # 6=model, 8=project_name, 9=project_version, 12=manufacturer,
    # 13=friendly_name, 16=suggested_area
    fields = _parse_all_string_fields(parsed[1])
    field_names = {
        2: "name", 3: "mac_address", 4: "esphome_version",
        5: "compilation_time", 6: "model", 8: "project_name",
        9: "project_version", 12: "manufacturer", 13: "friendly_name",
        16: "suggested_area",
    }
    return {field_names[k]: v for k, v in fields.items() if k in field_names and v.strip()}


async def _probe_esphome_web(ip: str, port: int = 80) -> dict[str, str]:
    """Fetch ESPHome web server SSE /events stream initial ping for title/uptime."""
    request = (
        f"GET /events HTTP/1.0\r\nHost: {ip}\r\nAccept: text/event-stream\r\n\r\n"
    ).encode()
    raw = await _read_banner(ip, port, send=request, timeout=3.0)
    if not raw:
        return {}
    text = raw.decode("utf-8", errors="replace")
    # Look for the SSE ping JSON: data: {"title": "...", ...}
    m = re.search(r'data:\s*(\{[^}]+\})', text)
    if not m:
        return {}
    try:
        import json as _json
        obj = _json.loads(m.group(1))
        result = {}
        if obj.get("title"):
            result["friendly_name"] = obj["title"]
        if obj.get("uptime") is not None:
            mins = int(float(obj["uptime"])) // 60
            result["uptime"] = f"{mins // 60}h {mins % 60}m" if mins >= 60 else f"{mins}m"
        return result
    except Exception:
        return {}


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

    Also runs ESPHome-specific probes when port 6053 is open or when an HTTP
    port responds like an ESPHome web server.
    """
    if not host.open_ports:
        return

    sem = asyncio.Semaphore(10)
    port_numbers = {p.port for p in host.open_ports}

    async def _probe_one(port_info: "PortInfo") -> None:
        async with sem:
            port = port_info.port
            version = port_info.version or ""

            if port == 6053:
                # ESPHome native API — richer than any banner
                info = await _probe_esphome_api(host.ip, port)
                if info:
                    _apply_esphome_info(host, info)
                    port_info.version = "ESPHome native API"
                    port_info.service = port_info.service or "esphomelib"
                return

            if port == 22 or port_info.service == "ssh":
                result = await _probe_ssh(host.ip, port)
            elif port in _HTTPS_PORTS or port_info.service in ("https", "https-alt"):
                result = await _probe_http(host.ip, port, tls=True)
            elif port in _HTTP_PORTS or port_info.service in ("http", "http-alt"):
                result = await _probe_http(host.ip, port, tls=False)
                # If this HTTP port might be an ESPHome web server, try /events
                if result and ("ESPHome" in result or "esphome" in result.lower()
                               or 6053 in port_numbers):
                    web_info = await _probe_esphome_web(host.ip, port)
                    if web_info:
                        _apply_esphome_info(host, web_info)
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
                if version and version not in result:
                    port_info.version = f"{version}  {result}"
                else:
                    port_info.version = result
                _apply_identity(host, result)

    # Run all port probes concurrently, then run ESPHome API probe if port present
    tasks = [_probe_one(p) for p in host.open_ports]

    # If 6053 is not already in open_ports but we suspect ESPHome (e.g. from
    # mDNS detection or Espressif OUI), try port 6053 anyway
    is_esphome = (
        6053 in port_numbers
        or "esphome" in " ".join(host.iot_info.detection_methods).lower()
        or "esphomelib" in " ".join(host.iot_info.mdns_services).lower()
        or (host.iot_info.vendor or "").lower() in ("espressif", "espressif inc.")
    )
    if is_esphome and 6053 not in port_numbers:
        async def _try_esphome_api() -> None:
            async with sem:
                info = await _probe_esphome_api(host.ip, 6053)
                if info:
                    _apply_esphome_info(host, info)
        tasks.append(_try_esphome_api())

    await asyncio.gather(*tasks, return_exceptions=True)


def _apply_esphome_info(host: "Host", info: dict[str, str]) -> None:
    """Merge ESPHome device info dict into host fields."""
    if not info:
        return
    existing = host.iot_info.esphome_info
    existing.update({k: v for k, v in info.items() if v})

    # Populate standard host/iot fields from ESPHome data
    if not host.iot_info.device_type:
        host.iot_info.device_type = "ESPHome Device"
    if not host.iot_info.vendor and info.get("manufacturer"):
        host.iot_info.vendor = info["manufacturer"]
    if not host.os_guess and info.get("esphome_version"):
        host.os_guess = f"ESPHome {info['esphome_version']}"

    # Use friendly_name or name as the mDNS display name if not set
    display = info.get("friendly_name") or info.get("name")
    if display and display not in host.iot_info.mdns_names:
        host.iot_info.mdns_names.insert(0, display)

    if "esphome-api" not in host.iot_info.detection_methods:
        host.iot_info.detection_methods.append("esphome-api")
