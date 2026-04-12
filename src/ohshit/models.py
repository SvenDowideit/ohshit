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
        return self.hostname or self.ip


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
