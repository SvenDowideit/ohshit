"""MAC OUI vendor lookup with IEEE database and permanence classification.

The IEEE publishes the full OUI registry as a CSV (~3.5 MB).  We download it
once to a local cache file and use it for all lookups.  If the download fails
or the cache is absent, we fall back to the bundled mini-table.

Permanence classification
--------------------------
A MAC address uniquely identifies a network interface, but some interfaces are
physically inseparable from their host while others are easily swapped:

  PERMANENT       — soldered/burned-in (SoC Wi-Fi, embedded Ethernet on IoT
                    devices, phones, tablets, smart TVs, printers, smart-home
                    controllers).  Changing it means changing the whole device.

  LIKELY_PERMANENT — integrated NIC on a laptop or desktop motherboard.
                    Technically replaceable but almost never is in practice.
                    Also covers managed switches and access points where the
                    NIC is part of the product identity.

  REMOVABLE       — add-in PCIe / M.2 / MiniPCIe network card.  Physically
                    separable; moving it moves the MAC with it.

  EXTERNAL        — USB network adapters, Thunderbolt docks with Ethernet,
                    USB-C multiport hubs.  Hot-pluggable, commonly shared
                    between machines.

  VIRTUAL         — hypervisor-assigned (VMware, VirtualBox, Hyper-V, QEMU,
                    Docker, WSL2, etc.).  The MAC tracks the VM/container,
                    not physical hardware.

  UNKNOWN         — no classification available.

Devices flagged REMOVABLE, EXTERNAL, or VIRTUAL should NOT be relied upon to
uniquely identify physical hardware across scans.
"""
from __future__ import annotations

import csv
import io
import logging
import re
import urllib.request
from pathlib import Path
from typing import NamedTuple

log = logging.getLogger(__name__)

# Where to cache the downloaded IEEE OUI CSV
_CACHE_PATH = Path.home() / ".cache" / "ohshit" / "oui.csv"
_IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class OuiInfo(NamedTuple):
    vendor: str
    permanence: str   # one of the PERMANENCE_* constants below


PERMANENCE_PERMANENT        = "permanent"
PERMANENCE_LIKELY_PERMANENT = "likely-permanent"
PERMANENCE_REMOVABLE        = "removable"
PERMANENCE_EXTERNAL         = "external"
PERMANENCE_VIRTUAL          = "virtual"
PERMANENCE_UNKNOWN          = "unknown"

PERMANENCE_LABELS = {
    PERMANENCE_PERMANENT:        "Permanent (embedded)",
    PERMANENCE_LIKELY_PERMANENT: "Likely permanent (integrated NIC)",
    PERMANENCE_REMOVABLE:        "Removable (add-in card)",
    PERMANENCE_EXTERNAL:         "External (USB/dock adapter)",
    PERMANENCE_VIRTUAL:          "Virtual (VM/container)",
    PERMANENCE_UNKNOWN:          "Unknown",
}

# ---------------------------------------------------------------------------
# Permanence rules applied to vendor name strings (case-insensitive substrings)
# Rules are checked in order; first match wins.
# ---------------------------------------------------------------------------

# Vendors whose products are almost always virtual interfaces
_VIRTUAL_VENDORS = [
    "vmware",
    "virtualbox",
    "oracle",          # VirtualBox OUIs
    "microsoft",       # Hyper-V virtual switch
    "parallels",
    "xensource",
    "red hat",         # virtio / KVM
    "qemu",
    "docker",
    "proxmox",
]

# Vendors whose adapters are almost always USB or dock-based
_EXTERNAL_VENDORS = [
    "asix",            # AX88x USB Ethernet chips (ubiquitous in USB adapters)
    "realtek",         # RTL8153/RTL8152 USB Ethernet (also in many docks)
    "plugable",        # USB docking stations
    "anker",           # USB hubs / docks
    "belkin",          # USB adapters / hubs
    "linksys",         # USB adapters
    "j5create",        # USB docks
    "startech",        # USB / Thunderbolt adapters
    "caldigit",        # Thunderbolt docks
    "club 3d",         # Thunderbolt docks
    "kensington",      # Docking stations
    "targus",          # Docking stations
    "lg innotek",      # USB-C docks on LG monitors
    "samsung electro-mechanics",  # USB devices
    "microchip",       # LAN7xxx USB Ethernet (Raspberry Pi CM, some docks)
    "smsc",            # USB Ethernet (older Raspberry Pi models)
]

# Vendors whose products are typically add-in PCIe/M.2 cards
_REMOVABLE_VENDORS = [
    "intel",           # Intel NICs are often add-in but also integrated
    "aquantia",        # High-speed PCIe NICs
    "chelsio",
    "solarflare",
    "mellanox",
    "broadcom",        # also embedded, but BCM57xxx is mostly PCIe
    "marvell",         # also embedded
    "fenvi",           # PCIe Wi-Fi cards
    "tp-link",         # PCIe Wi-Fi cards (also routers — handled below)
]

# Vendors whose products are almost always embedded/permanent
_PERMANENT_VENDORS = [
    # IoT SoC / modules
    "espressif",       # ESP32 / ESP8266 — Wi-Fi baked into SoC
    "raspberry pi",    # Integrated Ethernet / Wi-Fi on SBC
    "texas instruments",
    "nordic semiconductor",
    "silicon laboratories",
    "cypress semiconductor",
    "murata",          # Wi-Fi / BT modules soldered to boards
    "u-blox",
    "laird connectivity",
    # Smart home / consumer devices — MAC = device identity
    "philips",
    "nest",
    "sonos",
    "amazon",          # Echo, Fire devices
    "ikea",
    "xiaomi",
    "tuya",
    "shelly",
    "tasmota",
    # Routers / APs — the NIC is the product
    "ubiquiti",
    "netgear",
    "asus",
    "synology",
    "zyxel",
    "mikrotik",
    "avm",             # FRITZ!Box
    "draytek",
    "openwrt",
    # Printers / scanners
    "hp inc",
    "hewlett packard",
    "brother",
    "canon",
    "epson",
    "xerox",
    "lexmark",
    # Network storage
    "qnap",
    "buffalo",
    "western digital",
    # Smart TVs / media
    "samsung",
    "lg electronics",
    "roku",
    "google",          # Chromecast / Home — embedded Wi-Fi
    # Apple — all Apple NICs are soldered (MacBooks, iPhones, Apple TV)
    "apple",
]

# Vendors likely to have integrated (likely-permanent) NICs
_LIKELY_PERMANENT_VENDORS = [
    "intel",     # NUC, integrated laptop NICs (overrides removable below)
    "realtek",   # Also very common as integrated laptop/desktop NIC
    "marvell",   # Integrated server / NAS NICs
    "broadcom",  # Integrated in many laptops
    "atheros",   # Integrated Wi-Fi in many laptops
    "qualcomm",  # Integrated Wi-Fi / mobile
    "mediatek",  # Integrated Wi-Fi in phones and laptops
    "dell",
    "lenovo",
    "hewlett-packard",
    "acer",
    "toshiba",
    "fujitsu",
]

# ---------------------------------------------------------------------------
# Classify by vendor name
# ---------------------------------------------------------------------------

def classify_permanence(vendor: str) -> str:
    """Return a PERMANENCE_* constant based on vendor name heuristics."""
    vl = vendor.lower()

    for kw in _VIRTUAL_VENDORS:
        if kw in vl:
            return PERMANENCE_VIRTUAL

    for kw in _EXTERNAL_VENDORS:
        if kw in vl:
            return PERMANENCE_EXTERNAL

    for kw in _PERMANENT_VENDORS:
        if kw in vl:
            return PERMANENCE_PERMANENT

    # Integrated NIC vendors — check before removable since some names overlap
    for kw in _LIKELY_PERMANENT_VENDORS:
        if kw in vl:
            return PERMANENCE_LIKELY_PERMANENT

    for kw in _REMOVABLE_VENDORS:
        if kw in vl:
            return PERMANENCE_REMOVABLE

    return PERMANENCE_UNKNOWN


# ---------------------------------------------------------------------------
# In-memory lookup table (loaded lazily)
# ---------------------------------------------------------------------------

_oui_table: dict[str, OuiInfo] | None = None


def _load_table() -> dict[str, OuiInfo]:
    """Build the lookup table from cache CSV, or fall back to mini-table."""
    table: dict[str, OuiInfo] = {}
    source = _CACHE_PATH if _CACHE_PATH.exists() else None

    if source:
        try:
            with open(source, newline="", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # CSV columns: Registry, Assignment (hex, no colons), Organization Name
                    assignment = row.get("Assignment", "").strip().upper()
                    org = row.get("Organization Name", "").strip()
                    if len(assignment) == 6 and org:
                        # Normalise to "AA:BB:CC" format
                        oui = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}"
                        perm = classify_permanence(org)
                        table[oui] = OuiInfo(vendor=org, permanence=perm)
            log.debug("OUI table loaded: %d entries from %s", len(table), source)
            return table
        except Exception as exc:
            log.warning("Failed to load OUI cache: %s — using mini-table", exc)

    # Fall back to the built-in mini-table
    for oui_key, (vendor, _device_type) in _MINI_OUI.items():
        # Normalise key format
        normalised = _normalise_oui(oui_key)
        if normalised:
            perm = classify_permanence(vendor)
            table[normalised] = OuiInfo(vendor=vendor, permanence=perm)
    return table


def _normalise_oui(mac_prefix: str) -> str | None:
    """Convert any MAC prefix format to uppercase AA:BB:CC."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac_prefix)
    if len(cleaned) < 6:
        return None
    h = cleaned[:6].upper()
    return f"{h[0:2]}:{h[2:4]}:{h[4:6]}"


def _get_table() -> dict[str, OuiInfo]:
    global _oui_table
    if _oui_table is None:
        _oui_table = _load_table()
    return _oui_table


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_oui(mac: str | None) -> OuiInfo | None:
    """Return OuiInfo for the given MAC address, or None if not found."""
    if not mac:
        return None
    normalised = _normalise_oui(mac)
    if not normalised:
        return None
    return _get_table().get(normalised)


def refresh_cache(force: bool = False) -> bool:
    """Download the IEEE OUI CSV and save to cache.  Returns True on success.

    Called once at startup if the cache is absent or older than 30 days.
    Safe to call from a background thread.
    """
    global _oui_table

    import time
    if not force and _CACHE_PATH.exists():
        age_days = (time.time() - _CACHE_PATH.stat().st_mtime) / 86400
        if age_days < 30:
            return True  # Cache is fresh enough

    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        log.info("Downloading IEEE OUI registry from %s …", _IEEE_URL)
        req = urllib.request.Request(_IEEE_URL, headers={"User-Agent": "ohshit-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        _CACHE_PATH.write_bytes(data)
        _oui_table = None  # force reload on next lookup
        log.info("OUI cache saved to %s (%d bytes)", _CACHE_PATH, len(data))
        return True
    except Exception as exc:
        log.warning("OUI cache download failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Mini-table fallback (subset of well-known IoT/consumer OUIs)
# ---------------------------------------------------------------------------

_MINI_OUI: dict[str, tuple[str, str | None]] = {
    "e4:38:83": ("ASUS", "Router"),
    "b0:be:76": ("ASUS", "Router"),
    "14:eb:b6": ("Ubiquiti", "AP/Router"),
    "fc:ec:da": ("Ubiquiti", "AP/Router"),
    "00:27:22": ("Ubiquiti", "AP/Router"),
    "b4:fb:e4": ("Netgear", "Router"),
    "c0:3f:d5": ("Netgear", "Router"),
    "00:26:f2": ("Netgear", "Router"),
    "f8:1a:67": ("TP-Link", "Router"),
    "98:de:d0": ("TP-Link", "Router"),
    "50:c7:bf": ("TP-Link", "Router"),
    "28:d2:44": ("Synology", "NAS"),
    "00:11:32": ("Synology", "NAS"),
    "00:17:88": ("Philips", "Hue Hub"),
    "ec:b5:fa": ("Philips", "Hue"),
    "18:b4:30": ("Nest", "Thermostat/Camera"),
    "64:16:66": ("Nest", "Hub"),
    "a4:c1:38": ("Sonos", "Speaker"),
    "5c:aa:fd": ("Sonos", "Speaker"),
    "b8:e9:37": ("Apple", "TV/HomePod"),
    "3c:22:fb": ("Apple", "TV"),
    "f0:b4:29": ("Apple", "TV"),
    "f4:f1:5a": ("Google", "Home/Chromecast"),
    "54:60:09": ("Google", "Chromecast"),
    "6c:ad:f8": ("Google", "Home"),
    "8c:77:12": ("Samsung", "Smart TV"),
    "f8:04:2e": ("Samsung", "Smart TV"),
    "a0:b4:a5": ("LG Electronics", "Smart TV"),
    "64:9a:be": ("LG Electronics", "TV"),
    "68:c6:3a": ("Amazon", "Echo/Fire"),
    "fc:65:de": ("Amazon", "Echo"),
    "0c:47:c9": ("Amazon", "Kindle/Fire"),
    "b0:6e:bf": ("IKEA", "Tradfri Hub"),
    "ac:23:3f": ("Xiaomi", "IoT Device"),
    "f4:84:8d": ("Xiaomi", "Hub"),
    "10:6f:3f": ("Tuya/Smart Life", "IoT Device"),
    "7c:df:a1": ("Espressif", "IoT Device"),
    "e8:db:84": ("Espressif", "IoT Device"),
    "ec:fa:bc": ("Espressif", "IoT Device"),
    "00:1e:8f": ("HP", "Printer"),
    "3c:d9:2b": ("HP", "Printer"),
    "00:1b:a9": ("Brother", "Printer"),
    "dc:a6:32": ("Raspberry Pi Foundation", "SBC"),
    "b8:27:eb": ("Raspberry Pi Foundation", "SBC"),
    "e4:5f:01": ("Raspberry Pi Foundation", "SBC"),
    "d8:3a:dd": ("Raspberry Pi Foundation", "SBC"),
    # Common virtual/USB
    "00:50:56": ("VMware", None),
    "00:0c:29": ("VMware", None),
    "08:00:27": ("VirtualBox", None),
    "52:54:00": ("QEMU/KVM", None),
}
