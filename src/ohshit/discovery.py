from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
import socket
import struct
import xml.etree.ElementTree as ET
from typing import Callable, TypedDict

import aiofiles

from .models import Host, HostState, PortInfo, ScanResult


class DiscoveryError(Exception):
    pass


class NmapHostData(TypedDict):
    hostname: str | None
    os: str | None
    ports: list[PortInfo]
    mac: str | None


ProgressCallback = Callable[[str, int], None]


async def detect_local_subnet() -> tuple[str, str]:
    """Return (cidr, gateway_ip) using the interface that carries the default route.

    Strategy:
    1. Parse `ip route` to find the default gateway AND the interface it uses.
    2. Parse `ip addr show <iface>` to get the exact CIDR for that interface.
    3. Skip interfaces that are DOWN or carry only link-local / loopback addresses.
    This avoids picking up Docker bridge networks or other virtual adapters.
    """
    proc = await asyncio.create_subprocess_exec(
        "ip", "route",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    route_text = stdout.decode()

    gateway = None
    gw_iface = None
    for line in route_text.splitlines():
        # e.g. "default via 10.10.10.1 dev wlp0s20f3 proto dhcp ..."
        m = re.match(r"default via (\S+) dev (\S+)", line)
        if m:
            gateway = m.group(1)
            gw_iface = m.group(2)
            break

    cidr = None
    if gw_iface:
        # Ask for just that interface's addresses
        proc2 = await asyncio.create_subprocess_exec(
            "ip", "addr", "show", gw_iface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout2, _ = await proc2.communicate()
        for line in stdout2.decode().splitlines():
            # e.g. "    inet 10.10.13.208/20 brd 10.10.15.255 scope global ..."
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+).*scope global", line)
            if m:
                # Convert host address + prefix to network CIDR
                net = ipaddress.ip_interface(m.group(1)).network
                cidr = str(net)
                break

    if not gateway or not cidr:
        # Fallback: /proc/net/route — pick the non-default route on the same
        # interface as the default gateway, skipping linkdown bridges.
        try:
            async with aiofiles.open("/proc/net/route") as f:
                lines = await f.readlines()
            gw_iface_proc = None
            routes: list[tuple[str, str, str, str]] = []  # (iface, dest, gw, mask)
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 8:
                    continue
                iface = parts[0]
                dest_hex, gw_hex, mask_hex = parts[1], parts[2], parts[7]
                dest = socket.inet_ntoa(struct.pack("<I", int(dest_hex, 16)))
                gw   = socket.inet_ntoa(struct.pack("<I", int(gw_hex, 16)))
                if dest_hex == "00000000":
                    if not gateway:
                        gateway = gw
                    gw_iface_proc = iface
                else:
                    routes.append((iface, dest, gw_hex, mask_hex))
            # Now find the subnet route on the same interface as the default gw
            for iface, dest, gw_hex, mask_hex in routes:
                if iface == gw_iface_proc and gw_hex == "00000000" and mask_hex != "00000000":
                    prefix = bin(int(mask_hex, 16)).count("1")
                    cidr = f"{dest}/{prefix}"
                    break
        except OSError:
            pass

    if not gateway:
        raise DiscoveryError("Could not detect default gateway")
    if not cidr:
        parts = gateway.rsplit(".", 1)
        cidr = f"{parts[0]}.0/24"

    return cidr, gateway


async def read_local_arp_table() -> list[tuple[str, str]]:
    """Return [(ip, mac)] from local ARP table."""
    results: list[tuple[str, str]] = []
    try:
        async with aiofiles.open("/proc/net/arp") as f:
            lines = await f.readlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            ip, mac = parts[0], parts[3]
            if mac != "00:00:00:00:00:00":
                results.append((ip, mac))
        return results
    except OSError:
        pass

    # Fallback: arp -a
    proc = await asyncio.create_subprocess_exec(
        "arp", "-a",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    for line in stdout.decode().splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]{17})", line, re.IGNORECASE)
        if m:
            results.append((m.group(1), m.group(2)))
    return results


async def _ping_one(ip: str, sem: asyncio.Semaphore) -> str | None:
    async with sem:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c1", "-W1", str(ip),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()
        return str(ip) if proc.returncode == 0 else None


async def ping_sweep(cidr: str, timeout: float = 1.5) -> list[str]:
    """Return list of live IPs in the subnet via ICMP ping."""
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = list(network.hosts())[:254]
    sem = asyncio.Semaphore(50)
    tasks = [_ping_one(h, sem) for h in hosts]
    results = await asyncio.gather(*tasks)
    return [ip for ip in results if ip is not None]


def _parse_nmap_xml(xml_text: str) -> dict[str, NmapHostData]:
    results: dict[str, NmapHostData] = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return results

    for host_el in root.findall("host"):
        ip = None
        mac = None
        hostname = None
        os_guess = None
        ports: list[PortInfo] = []

        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")

        if not ip:
            continue

        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        os_el = host_el.find("os")
        if os_el is not None:
            best = os_el.find("osmatch")
            if best is not None:
                os_guess = best.get("name")

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                portid = int(port_el.get("portid", "0"))
                proto = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                service_el = port_el.find("service")
                service = ""
                version = ""
                if service_el is not None:
                    service = service_el.get("name", "")
                    product = service_el.get("product", "")
                    ver = service_el.get("version", "")
                    version = f"{product} {ver}".strip()
                ports.append(PortInfo(port=portid, protocol=proto, state=state, service=service, version=version))

        results[ip] = NmapHostData(hostname=hostname, os=os_guess, ports=ports, mac=mac)

    return results


async def nmap_scan(targets: list[str]) -> dict[str, NmapHostData]:
    """Run nmap against targets and return parsed host data."""
    if not targets or not shutil.which("nmap"):
        return {}

    args = ["nmap", "-sV", "--version-intensity", "3", "-T4", "-oX", "-"]
    if os.geteuid() == 0:
        args.append("-O")
    args.extend(targets)

    loop = asyncio.get_event_loop()

    def _run_nmap() -> str:
        import subprocess
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=120)
            return r.stdout
        except Exception:
            return ""

    xml_text = await loop.run_in_executor(None, _run_nmap)
    return _parse_nmap_xml(xml_text)


async def fetch_router_arp(gateway_ip: str) -> list[tuple[str, str]]:
    """Try to SSH into the gateway and retrieve its ARP table."""
    try:
        import asyncssh
        async with asyncssh.connect(
            gateway_ip,
            username=os.getenv("USER", ""),
            agent_forwarding=True,
            known_hosts=None,
            connect_timeout=5,
            login_timeout=8,
        ) as conn:
            result = await conn.run("arp -a 2>/dev/null || cat /proc/net/arp 2>/dev/null || true")
            output = result.stdout
        entries: list[tuple[str, str]] = []
        for line in output.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]{17})", line, re.IGNORECASE)
            if m:
                entries.append((m.group(1), m.group(2)))
        return entries
    except Exception:
        return []


async def discover_all(
    progress_cb: ProgressCallback | None = None,
    subnet_override: str | None = None,
) -> ScanResult:
    """Full discovery pipeline: ARP + ping + router ARP + nmap."""

    def prog(msg: str, pct: int) -> None:
        if progress_cb:
            progress_cb(msg, pct)

    result = ScanResult()

    prog("Detecting local subnet...", 2)
    try:
        if subnet_override:
            cidr = subnet_override
            # still try to detect gateway
            _, gateway = await detect_local_subnet()
        else:
            cidr, gateway = await detect_local_subnet()
    except DiscoveryError as e:
        prog(f"Subnet detection failed: {e}", 5)
        cidr = "192.168.1.0/24"
        gateway = "192.168.1.1"

    result.network_cidr = cidr
    result.gateway_ip = gateway
    prog(f"Subnet: {cidr}  Gateway: {gateway}", 5)

    prog("Reading local ARP table...", 8)
    arp_entries = await read_local_arp_table()
    hosts: dict[str, Host] = {}
    for ip, mac in arp_entries:
        try:
            socket.inet_aton(ip)
        except OSError:
            continue
        hosts[ip] = Host(ip=ip, mac=mac)

    prog(f"ARP table: {len(hosts)} hosts", 12)

    prog("Running ping sweep...", 15)
    live_ips = await ping_sweep(cidr)
    for ip in live_ips:
        if ip not in hosts:
            hosts[ip] = Host(ip=ip)
    prog(f"Ping sweep: {len(live_ips)} live hosts", 30)

    # Run router ARP + nmap concurrently
    prog("Running nmap + router ARP lookup...", 32)
    router_task = asyncio.create_task(fetch_router_arp(gateway))
    nmap_task = asyncio.create_task(nmap_scan(list(hosts.keys())))
    router_entries, nmap_data = await asyncio.gather(router_task, nmap_task, return_exceptions=True)

    if isinstance(router_entries, list):
        for ip, mac in router_entries:
            if ip not in hosts:
                hosts[ip] = Host(ip=ip, mac=mac)
            elif not hosts[ip].mac:
                hosts[ip].mac = mac
    prog("Router ARP done", 50)

    if isinstance(nmap_data, dict):
        for ip, data in nmap_data.items():
            if ip not in hosts:
                hosts[ip] = Host(ip=ip)
            h = hosts[ip]
            if data["hostname"] and not h.hostname:
                h.hostname = data["hostname"]
            if data["os"]:
                h.os_guess = data["os"]
            if data["mac"] and not h.mac:
                h.mac = data["mac"]
            h.open_ports = data["ports"]
    prog("nmap scan done", 70)

    # Attempt reverse DNS for unnamed hosts
    prog("Resolving hostnames...", 72)
    dns_tasks = []
    for h in hosts.values():
        if not h.hostname:
            dns_tasks.append(_resolve_hostname(h))
    if dns_tasks:
        await asyncio.gather(*dns_tasks, return_exceptions=True)

    result.hosts = hosts
    prog(f"Discovery complete: {len(hosts)} hosts found", 100)
    return result


async def _resolve_hostname(host: Host) -> None:
    try:
        loop = asyncio.get_event_loop()
        name, _, _ = await loop.run_in_executor(
            None, socket.gethostbyaddr, host.ip
        )
        host.hostname = name
    except Exception:
        pass
