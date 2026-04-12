from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class HostState(str, Enum):
    UNREACHABLE = "Unreachable"
    ALIVE = "Alive"
    SCANNING = "Scanning"
    SSH_SUCCESS = "SSH OK"
    SSH_FAILED = "SSH Failed"


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""


@dataclass
class Finding:
    host_ip: str
    category: str
    severity: Severity
    title: str
    description: str
    remediation: list[str]
    evidence: str = ""
    score: int = 0
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def __post_init__(self) -> None:
        if self.score == 0:
            self.score = {
                Severity.CRITICAL: 10,
                Severity.HIGH: 5,
                Severity.MEDIUM: 2,
                Severity.LOW: 1,
                Severity.INFO: 0,
            }[self.severity]


@dataclass
class MacEvent:
    """Records a MAC address seen at a given IP at a point in time.

    Used to detect hardware repurposing: if a MAC moves to a different IP,
    or a new MAC appears at a known IP, both events are stored.
    """
    mac: str
    ip: str
    first_seen: datetime
    last_seen: datetime
    hostname: str | None = None
    os_guess: str | None = None


@dataclass
class IotInfo:
    """Passively gathered IoT identification data."""
    vendor: str | None = None          # from MAC OUI
    device_type: str | None = None     # "Smart TV", "Router", "Hub", etc.
    mdns_names: list[str] = field(default_factory=list)   # from mDNS
    mdns_services: list[str] = field(default_factory=list)
    upnp_friendly_name: str | None = None
    upnp_model: str | None = None
    ha_entity_id: str | None = None    # Home Assistant entity
    mqtt_topics: list[str] = field(default_factory=list)
    banner_grabs: dict[int, str] = field(default_factory=dict)  # port→banner
    detection_methods: list[str] = field(default_factory=list)


@dataclass
class Host:
    ip: str
    mac: str | None = None
    hostname: str | None = None
    state: HostState = HostState.ALIVE
    os_guess: str | None = None
    kernel_version: str | None = None
    os_release: dict[str, str] = field(default_factory=dict)
    open_ports: list[PortInfo] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    scan_time: datetime | None = None
    ssh_error: str | None = None

    # Persistence / history fields
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    last_scan: datetime | None = None

    # IoT passive detection
    iot_info: IotInfo = field(default_factory=IotInfo)

    # Hardware repurposing detection: previous MACs seen at this IP
    mac_history: list[MacEvent] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        return sum(f.score for f in self.findings)

    @property
    def risk_label(self) -> Severity:
        s = self.risk_score
        if s >= 30:
            return Severity.CRITICAL
        if s >= 15:
            return Severity.HIGH
        if s >= 8:
            return Severity.MEDIUM
        if s > 0:
            return Severity.LOW
        return Severity.INFO

    @property
    def display_name(self) -> str:
        # Prefer mDNS name, then hostname, then UPnP name, then IP
        if self.iot_info.mdns_names:
            return self.iot_info.mdns_names[0]
        return self.hostname or self.iot_info.upnp_friendly_name or self.ip

    @property
    def vendor(self) -> str | None:
        return self.iot_info.vendor

    @property
    def is_repurposed(self) -> bool:
        """True if this IP has had multiple distinct MACs, or this MAC has moved IPs."""
        macs = {e.mac for e in self.mac_history}
        if self.mac:
            macs.add(self.mac)
        return len(macs) > 1

    @property
    def repurpose_note(self) -> str | None:
        if not self.is_repurposed:
            return None
        macs = [e.mac for e in self.mac_history]
        if self.mac and self.mac not in macs:
            macs.append(self.mac)
        return f"Hardware change detected — previously seen MACs: {', '.join(dict.fromkeys(macs))}"


@dataclass
class ScanResult:
    hosts: dict[str, Host] = field(default_factory=dict)
    scan_start: datetime = field(default_factory=datetime.now)
    scan_end: datetime | None = None
    network_cidr: str | None = None
    gateway_ip: str | None = None

    @property
    def network_risk_score(self) -> int:
        if not self.hosts:
            return 0
        scores = [h.risk_score for h in self.hosts.values()]
        return max(scores) + int(sum(scores) / len(scores))

    @property
    def network_risk_label(self) -> Severity:
        s = self.network_risk_score
        if s >= 30:
            return Severity.CRITICAL
        if s >= 15:
            return Severity.HIGH
        if s >= 8:
            return Severity.MEDIUM
        if s > 0:
            return Severity.LOW
        return Severity.INFO
