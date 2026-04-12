"""Passive and lightweight IoT / device identification.

All detectors are async and non-destructive.  They add data to IotInfo
without modifying anything on target devices.

Detectors
---------
1. MAC OUI lookup — vendor + permanence from IEEE registry (see oui_db.py).
2. mDNS sniff     — read _services._dns-sd._udp.local for 2 s.
3. SSDP / UPnP    — send one M-SEARCH, collect responses for 3 s.
4. Banner grabs   — TCP connect on common IoT ports, read first 512 bytes.
5. Home Assistant — probe http(s)://host:8123/api/ with optional HA token.
6. MQTT probe     — attempt CONNECT on 1883/8883, check for CONNACK.
"""
from __future__ import annotations

import asyncio
import re
import socket
import struct
from typing import Any

import aiohttp

from .models import IotInfo
from .oui_db import lookup_oui

# ---------------------------------------------------------------------------
# Common IoT ports for banner grabbing
# ---------------------------------------------------------------------------

# Common IoT ports for banner grabbing
_IOT_PORTS: list[tuple[int, str]] = [
    (80,   "http"),
    (443,  "https"),
    (8080, "http-alt"),
    (8123, "home-assistant"),
    (8883, "mqtt-tls"),
    (1883, "mqtt"),
    (5683, "coap"),
    (8008, "chromecast"),
    (8009, "chromecast-tls"),
    (9123, "hue-bridge"),
    (554,  "rtsp"),
    (1900, "upnp"),
    (5353, "mdns"),
]


def lookup_oui(mac: str | None) -> tuple[str | None, str | None]:
    """Return (vendor, device_type) from a MAC address OUI prefix."""
    if not mac:
        return None, None
    prefix = mac.lower()[:8]  # "aa:bb:cc"
    entry = _OUI.get(prefix)
    if entry:
        return entry
    # Also try 6-char hex without colons
    hex6 = mac.replace(":", "").replace("-", "").lower()[:6]
    for key, val in _OUI.items():
        if key.replace(":", "") == hex6:
            return val
    return None, None


# ---------------------------------------------------------------------------
# 2. mDNS sniff (passive, no queries sent)
# ---------------------------------------------------------------------------

async def sniff_mdns(timeout: float = 3.0) -> dict[str, IotInfo]:
    """Listen on 224.0.0.251:5353 for mDNS announcements.

    Returns {ip: IotInfo} for any device that self-announces.
    """
    results: dict[str, IotInfo] = {}
    try:
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _MDNSProtocol(results),
            local_addr=("0.0.0.0", 5353),
            family=socket.AF_INET,
            allow_broadcast=True,
        )
        # Join multicast group
        sock = transport.get_extra_info("socket")
        group = struct.pack("4s4s",
            socket.inet_aton("224.0.0.251"),
            socket.inet_aton("0.0.0.0"))
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group)
        except OSError:
            pass  # Already member or not supported
        await asyncio.sleep(timeout)
        transport.close()
    except Exception:
        pass
    return results


class _MDNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, results: dict[str, IotInfo]) -> None:
        self._results = results

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        ip = addr[0]
        if ip.startswith("169.254") or ip == "127.0.0.1":
            return
        names, services = _parse_mdns_minimal(data)
        if not names and not services:
            return
        if ip not in self._results:
            self._results[ip] = IotInfo(detection_methods=["mDNS"])
        info = self._results[ip]
        for n in names:
            if n not in info.mdns_names:
                info.mdns_names.append(n)
        for s in services:
            if s not in info.mdns_services:
                info.mdns_services.append(s)


def _parse_mdns_minimal(data: bytes) -> tuple[list[str], list[str]]:
    """Very minimal DNS packet parser — extract PTR/SRV name strings."""
    names: list[str] = []
    services: list[str] = []
    try:
        # Skip 12-byte header, try to extract readable labels
        offset = 12
        while offset < len(data) - 4:
            length = data[offset]
            if length == 0:
                offset += 1
                continue
            if length & 0xC0 == 0xC0:  # pointer
                offset += 2
                continue
            if offset + length + 1 > len(data):
                break
            label = data[offset + 1: offset + 1 + length]
            try:
                text = label.decode("utf-8", errors="ignore")
                if "._tcp" in text or "._udp" in text:
                    services.append(text)
                elif ".local" in text or len(text) > 2:
                    names.append(text)
            except Exception:
                pass
            offset += length + 1
    except Exception:
        pass
    return names, services


# ---------------------------------------------------------------------------
# 3. SSDP / UPnP
# ---------------------------------------------------------------------------

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {_SSDP_ADDR}:{_SSDP_PORT}\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()


async def sniff_ssdp(timeout: float = 4.0) -> dict[str, IotInfo]:
    """Send one SSDP M-SEARCH and collect UPnP responses."""
    results: dict[str, IotInfo] = {}
    try:
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _SSDPProtocol(results),
            local_addr=("0.0.0.0", 0),
            family=socket.AF_INET,
            allow_broadcast=True,
        )
        transport.sendto(_MSEARCH, (_SSDP_ADDR, _SSDP_PORT))
        await asyncio.sleep(timeout)
        transport.close()
    except Exception:
        pass
    return results


class _SSDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, results: dict[str, IotInfo]) -> None:
        self._results = results

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        ip = addr[0]
        text = data.decode("utf-8", errors="ignore")
        if ip not in self._results:
            self._results[ip] = IotInfo(detection_methods=["SSDP/UPnP"])
        info = self._results[ip]
        # Extract LOCATION header for UPnP description URL
        loc_m = re.search(r"LOCATION:\s*(\S+)", text, re.IGNORECASE)
        if loc_m:
            asyncio.ensure_future(_fetch_upnp_desc(ip, loc_m.group(1), info))
        # Extract SERVER header
        srv_m = re.search(r"SERVER:\s*(.+)", text, re.IGNORECASE)
        if srv_m and not info.device_type:
            info.device_type = srv_m.group(1).strip()[:80]


async def _fetch_upnp_desc(ip: str, url: str, info: IotInfo) -> None:
    """Fetch UPnP device description XML and extract friendly name/model."""
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=5),
            connector=aiohttp.TCPConnector(ssl=False),
        ) as session:
            async with session.get(url) as resp:
                xml = await resp.text(errors="ignore")
        fn = re.search(r"<friendlyName>([^<]+)</friendlyName>", xml)
        if fn:
            info.upnp_friendly_name = fn.group(1).strip()
        mn = re.search(r"<modelName>([^<]+)</modelName>", xml)
        if mn:
            info.upnp_model = mn.group(1).strip()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 4. Banner grabs on common IoT ports
# ---------------------------------------------------------------------------

async def banner_grab(ip: str, ports: list[int] | None = None, timeout: float = 2.0) -> dict[int, str]:
    """Try TCP connect on each port, return {port: banner} for open ones."""
    if ports is None:
        ports = [p for p, _ in _IOT_PORTS]
    banners: dict[int, str] = {}
    sem = asyncio.Semaphore(10)

    async def _grab(port: int) -> None:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                try:
                    # Send a minimal HTTP GET for web ports, else just read
                    if port in (80, 8080, 8123, 8008):
                        writer.write(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                        await writer.drain()
                    raw = await asyncio.wait_for(reader.read(512), timeout=timeout)
                    text = raw.decode("utf-8", errors="replace").strip()
                    if text:
                        banners[port] = text[:200]
                finally:
                    writer.close()
            except Exception:
                pass

    await asyncio.gather(*[_grab(p) for p in ports])
    return banners


def classify_from_banners(banners: dict[int, str], info: IotInfo) -> None:
    """Update IotInfo based on HTTP banner content."""
    for port, banner in banners.items():
        bl = banner.lower()
        if "home assistant" in bl or "hass.io" in bl:
            if "home-assistant" not in info.detection_methods:
                info.detection_methods.append("banner:home-assistant")
            info.device_type = info.device_type or "Home Assistant"
        elif "mqtt" in bl or "mosquitto" in bl:
            if "banner:mqtt" not in info.detection_methods:
                info.detection_methods.append("banner:mqtt")
            info.device_type = info.device_type or "MQTT Broker"
        elif "synology" in bl:
            info.device_type = info.device_type or "Synology NAS"
        elif "plex" in bl:
            info.device_type = info.device_type or "Plex Media Server"
        elif "pi-hole" in bl:
            info.device_type = info.device_type or "Pi-hole"
        elif "openwrt" in bl:
            info.device_type = info.device_type or "OpenWrt Router"
        elif "fritz" in bl:
            info.device_type = info.device_type or "AVM FRITZ!Box"
        elif "unifi" in bl:
            info.device_type = info.device_type or "Ubiquiti UniFi"
        info.banner_grabs[port] = banners[port]


# ---------------------------------------------------------------------------
# 5. Home Assistant probe
# ---------------------------------------------------------------------------

async def probe_home_assistant(
    ip: str,
    token: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    """Check if the host is running Home Assistant on port 8123."""
    for scheme in ("http", "https"):
        url = f"{scheme}://{ip}:8123/api/"
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout),
                connector=aiohttp.TCPConnector(ssl=False),
            ) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status in (200, 401):
                        try:
                            data = await resp.json(content_type=None)
                        except Exception:
                            data = {}
                        return {"url": url, "status": resp.status, "data": data}
        except Exception:
            pass
    return None


# ---------------------------------------------------------------------------
# 6. MQTT probe
# ---------------------------------------------------------------------------

async def probe_mqtt(ip: str, port: int = 1883, timeout: float = 3.0) -> list[str]:
    """Send a minimal MQTT CONNECT and return topic hints from CONNACK/error."""
    topics: list[str] = []
    # Minimal MQTT CONNECT packet (protocol level 4 = MQTT 3.1.1, clean session)
    client_id = b"ohshit-probe"
    connect = (
        b"\x10"  # CONNECT
        + _mqtt_encode_len(10 + 2 + len(client_id))
        + b"\x00\x04MQTT"   # protocol name
        + b"\x04"            # protocol level 3.1.1
        + b"\x02"            # flags: clean session
        + b"\x00\x3c"        # keepalive 60s
        + b"\x00" + bytes([len(client_id)]) + client_id
    )
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(connect)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4), timeout=timeout)
        writer.close()
        if response and response[0] == 0x20:  # CONNACK
            topics.append(f"mqtt://{ip}:{port}")
    except Exception:
        pass
    return topics


def _mqtt_encode_len(n: int) -> bytes:
    result = bytearray()
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 128
        result.append(byte)
        if n == 0:
            break
    return bytes(result)


# ---------------------------------------------------------------------------
# High-level: run all detectors for a single host
# ---------------------------------------------------------------------------

async def detect_iot(
    ip: str,
    mac: str | None = None,
    is_ssh_accessible: bool = False,
    ha_token: str | None = None,
) -> IotInfo:
    """Run all passive IoT detectors for one host and return merged IotInfo."""
    info = IotInfo()

    # OUI lookup (instant) — uses IEEE registry if cached, else mini-table
    oui = lookup_oui(mac)
    if oui:
        info.vendor = oui.vendor
        info.mac_permanence = oui.permanence
        info.detection_methods.append("OUI")
        # device_type is not in the full IEEE DB; only the mini-table has it.
        # We leave it to banner/SSDP/mDNS to fill in for the full-DB case.

    # Banner grabs (skip SSH port 22 on SSH-accessible hosts to reduce noise)
    skip_ports = [22] if is_ssh_accessible else []
    grab_ports = [p for p, _ in _IOT_PORTS if p not in skip_ports]
    banners = await banner_grab(ip, grab_ports)
    if banners:
        classify_from_banners(banners, info)
        if "banner" not in " ".join(info.detection_methods):
            info.detection_methods.append("banner-grab")

    # Home Assistant probe
    ha = await probe_home_assistant(ip, token=ha_token)
    if ha:
        info.device_type = info.device_type or "Home Assistant"
        if "home-assistant" not in info.detection_methods:
            info.detection_methods.append("home-assistant")

    # MQTT probe on both plain and TLS ports
    for mqtt_port in (1883, 8883):
        topics = await probe_mqtt(ip, mqtt_port)
        info.mqtt_topics.extend(topics)
        if topics and "mqtt" not in info.detection_methods:
            info.detection_methods.append("mqtt")

    return info


# ---------------------------------------------------------------------------
# Network-wide passive listeners (run once per scan, not per host)
# ---------------------------------------------------------------------------

async def passive_network_scan(timeout: float = 4.0) -> dict[str, IotInfo]:
    """Run mDNS + SSDP listeners concurrently and merge results."""
    mdns_task = asyncio.create_task(sniff_mdns(timeout))
    ssdp_task = asyncio.create_task(sniff_ssdp(timeout))
    mdns_results, ssdp_results = await asyncio.gather(mdns_task, ssdp_task, return_exceptions=True)

    merged: dict[str, IotInfo] = {}
    if isinstance(mdns_results, dict):
        merged.update(mdns_results)
    if isinstance(ssdp_results, dict):
        for ip, iot in ssdp_results.items():
            if ip in merged:
                merged[ip].mdns_services.extend(iot.mdns_services)
                merged[ip].upnp_friendly_name = merged[ip].upnp_friendly_name or iot.upnp_friendly_name
                merged[ip].upnp_model = merged[ip].upnp_model or iot.upnp_model
                for m in iot.detection_methods:
                    if m not in merged[ip].detection_methods:
                        merged[ip].detection_methods.append(m)
            else:
                merged[ip] = iot
    return merged
