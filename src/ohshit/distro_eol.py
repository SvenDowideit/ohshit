"""Distro end-of-life (EOL) and long-term-support (LTS) date lookup.

Data is maintained manually and is accurate as of 2026-04.  When a distro
version is not in the table it means either it is unknown or not yet EOL.

Sources:
  - Ubuntu: https://wiki.ubuntu.com/Releases
  - Debian: https://wiki.debian.org/LTS
  - Raspberry Pi OS: based on upstream Debian release lifecycle
  - RHEL: https://access.redhat.com/product-life-cycles
  - CentOS Stream: https://wiki.centos.org/About/Product
  - Fedora: ~13 months per release (EOL after two subsequent releases)
  - Alpine: https://alpinelinux.org/releases/
  - openSUSE Leap: https://en.opensuse.org/Lifetime
  - Amazon Linux: https://aws.amazon.com/amazon-linux-2/faqs/
  - Oracle Linux: same as RHEL lifecycle
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class EolInfo:
    distro_id: str          # canonical key e.g. "ubuntu"
    version: str            # e.g. "22.04"
    pretty: str             # human-readable e.g. "Ubuntu 22.04 LTS (Jammy)"
    eol_date: date          # end of *standard* support
    lts_eol_date: date | None  # end of extended/LTS support (if different)
    successor: str | None   # immediate next release (may be STS/non-LTS)
    support_type: str       # "LTS", "STS", "Standard", "Extended"
    next_lts: str | None = None  # nearest LTS release (may equal successor)

    @property
    def is_eol(self) -> bool:
        return date.today() >= self.eol_date

    @property
    def is_lts_eol(self) -> bool:
        if self.lts_eol_date is None:
            return self.is_eol
        return date.today() >= self.lts_eol_date

    @property
    def days_until_eol(self) -> int:
        """Days until standard EOL (negative means already EOL)."""
        return (self.eol_date - date.today()).days

    @property
    def days_until_lts_eol(self) -> int:
        """Days until extended/LTS EOL (negative means already EOL)."""
        target = self.lts_eol_date or self.eol_date
        return (target - date.today()).days

    @property
    def effective_eol(self) -> date:
        """The latest supported date (lts_eol_date if set, else eol_date)."""
        return self.lts_eol_date if self.lts_eol_date else self.eol_date

    @property
    def effective_days_remaining(self) -> int:
        return (self.effective_eol - date.today()).days

    @property
    def successor_is_lts(self) -> bool:
        """True when the immediate successor is also the nearest LTS (or no LTS alternative)."""
        return self.next_lts is None or self.next_lts == self.successor


# ---------------------------------------------------------------------------
# EOL database
# Keys: (distro_id_lower, version_id)
# distro_id comes from /etc/os-release ID= field
# ---------------------------------------------------------------------------

_EOL_DATA: dict[tuple[str, str], EolInfo] = {}


def _add(distro_id: str, version: str, pretty: str, eol_date: date,
         lts_eol_date: date | None, successor: str | None, support_type: str,
         next_lts: str | None = None) -> None:
    info = EolInfo(
        distro_id=distro_id, version=version, pretty=pretty,
        eol_date=eol_date, lts_eol_date=lts_eol_date,
        successor=successor, support_type=support_type,
        next_lts=next_lts if next_lts != successor else None,
    )
    _EOL_DATA[(distro_id.lower(), version)] = info


# ── Ubuntu ───────────────────────────────────────────────────────────────────
# Standard support ends 5 years after release for LTS, ~9 months for interim.
# Extended Security Maintenance (ESM) adds 5 more years for LTS.
# next_lts: nearest LTS target when successor is an STS release.
_add("ubuntu", "16.04", "Ubuntu 16.04 LTS (Xenial)",      date(2021, 4, 30),  date(2026, 4, 30),  "20.04", "LTS")
_add("ubuntu", "18.04", "Ubuntu 18.04 LTS (Bionic)",      date(2023, 4, 30),  date(2028, 4, 30),  "22.04", "LTS")
_add("ubuntu", "20.04", "Ubuntu 20.04 LTS (Focal)",       date(2025, 4,  2),  date(2030, 4, 30),  "24.04", "LTS")
_add("ubuntu", "21.10", "Ubuntu 21.10 (Impish)",          date(2022, 7, 14),  None,               "22.04", "STS")
_add("ubuntu", "22.04", "Ubuntu 22.04 LTS (Jammy)",       date(2027, 4, 30),  date(2032, 4, 30),  "24.04", "LTS")
_add("ubuntu", "22.10", "Ubuntu 22.10 (Kinetic)",         date(2023, 7, 20),  None,               "23.04", "STS",  next_lts="24.04")
_add("ubuntu", "23.04", "Ubuntu 23.04 (Lunar)",           date(2024, 1, 25),  None,               "23.10", "STS",  next_lts="24.04")
_add("ubuntu", "23.10", "Ubuntu 23.10 (Mantic)",          date(2024, 7, 11),  None,               "24.04", "STS")
_add("ubuntu", "24.04", "Ubuntu 24.04 LTS (Noble)",       date(2029, 4, 30),  date(2034, 4, 30),  "26.04", "LTS")
_add("ubuntu", "24.10", "Ubuntu 24.10 (Oracular)",        date(2025, 7, 17),  None,               "25.04", "STS",  next_lts="26.04")
_add("ubuntu", "25.04", "Ubuntu 25.04 (Plucky)",          date(2026, 1,  1),  None,               "25.10", "STS",  next_lts="26.04")

# ── Debian ───────────────────────────────────────────────────────────────────
# LTS support (Freexian/community) extends ~2 years beyond EOL for oldstable.
_add("debian", "9",  "Debian 9 (Stretch)",    date(2022,  6, 30), date(2022,  6, 30), "12", "Standard")
_add("debian", "10", "Debian 10 (Buster)",    date(2022,  9, 10), date(2024,  6, 30), "12", "LTS")
_add("debian", "11", "Debian 11 (Bullseye)",  date(2024,  8, 31), date(2026,  6, 30), "12", "LTS")
_add("debian", "12", "Debian 12 (Bookworm)",  date(2026,  6, 30), date(2028,  6, 30), "13", "LTS")
_add("debian", "13", "Debian 13 (Trixie)",    date(2028,  6, 30), date(2030,  6, 30), None, "LTS")

# ── Raspberry Pi OS ──────────────────────────────────────────────────────────
# Raspberry Pi OS tracks Debian closely; use same EOL timeline as base Debian.
# VERSION_ID is not always set; we also match VERSION_CODENAME.
_add("raspbian", "10", "Raspberry Pi OS 10 (Buster)",   date(2022,  9, 10), date(2024,  6, 30), "12", "LTS")
_add("raspbian", "11", "Raspberry Pi OS 11 (Bullseye)", date(2024,  8, 31), date(2026,  6, 30), "12", "LTS")
_add("raspbian", "12", "Raspberry Pi OS 12 (Bookworm)", date(2026,  6, 30), date(2028,  6, 30), "13", "LTS")

# ── RHEL / Red Hat Enterprise Linux ──────────────────────────────────────────
_add("rhel", "7",  "RHEL 7",  date(2019,  8,  6), date(2024,  6, 30), "9",  "Extended")
_add("rhel", "8",  "RHEL 8",  date(2024,  5, 31), date(2029,  5, 31), "9",  "Extended")
_add("rhel", "9",  "RHEL 9",  date(2027,  5, 31), date(2032,  5, 31), "10", "Extended")
_add("rhel", "10", "RHEL 10", date(2030,  5, 31), date(2035,  5, 31), None, "Extended")

# ── CentOS ───────────────────────────────────────────────────────────────────
_add("centos", "6",       "CentOS 6",        date(2020, 11, 30), None,               "stream9", "Standard")
_add("centos", "7",       "CentOS 7",        date(2024,  6, 30), None,               "stream9", "Standard")
_add("centos", "8",       "CentOS 8",        date(2021, 12, 31), None,               "stream9", "Standard")
_add("centos", "stream8", "CentOS Stream 8", date(2024,  5, 31), None,               "stream9", "Standard")
_add("centos", "stream9", "CentOS Stream 9", date(2027,  5, 31), None,              "stream10", "Standard")
_add("centos", "stream10","CentOS Stream 10",date(2030,  5, 31), None,               None,      "Standard")

# ── Fedora ───────────────────────────────────────────────────────────────────
# Fedora releases are EOL ~13 months after release (one month after N+2 ships).
_add("fedora", "37", "Fedora 37", date(2023, 12, 15), None, "40", "Standard")
_add("fedora", "38", "Fedora 38", date(2024,  5, 21), None, "40", "Standard")
_add("fedora", "39", "Fedora 39", date(2024, 11, 26), None, "41", "Standard")
_add("fedora", "40", "Fedora 40", date(2025,  5, 13), None, "42", "Standard")
_add("fedora", "41", "Fedora 41", date(2025, 11, 18), None, "42", "Standard")
_add("fedora", "42", "Fedora 42", date(2026,  5, 19), None, "43", "Standard")

# ── Alpine Linux ─────────────────────────────────────────────────────────────
# Each stable branch is supported for ~2 years.
_add("alpine", "3.15", "Alpine 3.15", date(2023, 11,  1), None, "3.19", "Standard")
_add("alpine", "3.16", "Alpine 3.16", date(2024,  5, 23), None, "3.19", "Standard")
_add("alpine", "3.17", "Alpine 3.17", date(2024, 11, 22), None, "3.20", "Standard")
_add("alpine", "3.18", "Alpine 3.18", date(2025,  5,  9), None, "3.21", "Standard")
_add("alpine", "3.19", "Alpine 3.19", date(2025, 11, 22), None, "3.21", "Standard")
_add("alpine", "3.20", "Alpine 3.20", date(2026,  4, 10), None, "3.21", "Standard")
_add("alpine", "3.21", "Alpine 3.21", date(2026, 11,  1), None, "3.22", "Standard")

# ── openSUSE Leap ────────────────────────────────────────────────────────────
_add("opensuse-leap", "15.3", "openSUSE Leap 15.3", date(2022, 12,  1), None, "15.6", "Standard")
_add("opensuse-leap", "15.4", "openSUSE Leap 15.4", date(2023, 12,  1), None, "15.6", "Standard")
_add("opensuse-leap", "15.5", "openSUSE Leap 15.5", date(2024, 12,  1), None, "15.6", "Standard")
_add("opensuse-leap", "15.6", "openSUSE Leap 15.6", date(2025, 12,  1), None, "16.0", "Standard")

# ── Amazon Linux ─────────────────────────────────────────────────────────────
_add("amzn", "2",    "Amazon Linux 2",    date(2025,  6, 30), None, "2023", "Standard")
_add("amzn", "2023", "Amazon Linux 2023", date(2028,  3,  1), None, None,   "Standard")

# ── Oracle Linux ─────────────────────────────────────────────────────────────
_add("ol", "7", "Oracle Linux 7", date(2024, 12, 31), None, "9",  "Extended")
_add("ol", "8", "Oracle Linux 8", date(2029,  7, 31), None, "9",  "Extended")
_add("ol", "9", "Oracle Linux 9", date(2032,  6, 30), None, "10", "Extended")

# ── Rocky Linux ──────────────────────────────────────────────────────────────
_add("rocky", "8", "Rocky Linux 8", date(2029,  5, 31), None, "9",  "Standard")
_add("rocky", "9", "Rocky Linux 9", date(2032,  5, 31), None, "10", "Standard")

# ── AlmaLinux ────────────────────────────────────────────────────────────────
_add("almalinux", "8", "AlmaLinux 8", date(2029,  3, 31), None, "9",  "Standard")
_add("almalinux", "9", "AlmaLinux 9", date(2032,  5, 31), None, "10", "Standard")


# ---------------------------------------------------------------------------
# Codename → (distro_id, version_id) fallback map
# Used when VERSION_ID is absent or unhelpful (e.g. some Raspberry Pi images)
# ---------------------------------------------------------------------------

_CODENAME_MAP: dict[str, tuple[str, str]] = {
    # Debian codenames
    "buster":    ("debian",   "10"),
    "bullseye":  ("debian",   "11"),
    "bookworm":  ("debian",   "12"),
    "trixie":    ("debian",   "13"),
    "forky":     ("debian",   "14"),
    "stretch":   ("debian",    "9"),
    "jessie":    ("debian",    "8"),
    # Ubuntu codenames
    "xenial":    ("ubuntu",  "16.04"),
    "bionic":    ("ubuntu",  "18.04"),
    "focal":     ("ubuntu",  "20.04"),
    "impish":    ("ubuntu",  "21.10"),
    "jammy":     ("ubuntu",  "22.04"),
    "kinetic":   ("ubuntu",  "22.10"),
    "lunar":     ("ubuntu",  "23.04"),
    "mantic":    ("ubuntu",  "23.10"),
    "noble":     ("ubuntu",  "24.04"),
    "oracular":  ("ubuntu",  "24.10"),
    "plucky":    ("ubuntu",  "25.04"),
}


def get_eol_info(os_release: dict[str, str]) -> EolInfo | None:
    """Return EOL information for the given /etc/os-release dict, or None if unknown.

    Tries the following in order:
    1. (ID, VERSION_ID)  — most precise
    2. (ID_LIKE, VERSION_ID) — for derivatives that set ID_LIKE=debian/rhel/etc.
    3. Codename lookup via VERSION_CODENAME or UBUNTU_CODENAME
    4. Major version only (e.g. "8" from "8.5")
    """
    distro_id = os_release.get("ID", "").lower().strip()
    version_id = os_release.get("VERSION_ID", "").strip().strip('"')
    codename = (
        os_release.get("VERSION_CODENAME", "")
        or os_release.get("UBUNTU_CODENAME", "")
    ).lower().strip()
    id_like = os_release.get("ID_LIKE", "").lower()

    # 1. Direct match
    if distro_id and version_id:
        info = _EOL_DATA.get((distro_id, version_id))
        if info:
            return info

    # 2. Raspbian → check raspbian table, then debian table
    if distro_id in ("raspbian",) and version_id:
        info = _EOL_DATA.get(("debian", version_id))
        if info:
            # Return a raspbian-flavoured copy
            return EolInfo(
                distro_id="raspbian",
                version=info.version,
                pretty=f"Raspberry Pi OS (based on Debian {info.version})",
                eol_date=info.eol_date,
                lts_eol_date=info.lts_eol_date,
                successor=info.successor,
                support_type=info.support_type,
            )

    # 3. ID_LIKE fallback (e.g. Linux Mint sets ID=linuxmint, ID_LIKE=ubuntu)
    if id_like and version_id:
        for parent in id_like.split():
            info = _EOL_DATA.get((parent, version_id))
            if info:
                return info

    # 4. Codename lookup
    if codename and codename in _CODENAME_MAP:
        mapped_id, mapped_ver = _CODENAME_MAP[codename]
        info = _EOL_DATA.get((mapped_id, mapped_ver))
        if info:
            return info

    # 5. Major version only (e.g. "8.5" → "8", useful for RHEL/Rocky/etc.)
    if distro_id and version_id and "." in version_id:
        major = version_id.split(".")[0]
        info = _EOL_DATA.get((distro_id, major))
        if info:
            return info

    return None


def eol_badge_text(info: EolInfo) -> tuple[str, str]:
    """Return (badge_label, css_class) for a host list EOL badge.

    Returns ("", "") when the distro is in full support with >180 days left.
    """
    days = info.effective_days_remaining

    if days < 0:
        return ("EOL", "eol-badge-critical")
    if days < 90:
        return ("EOL<90d", "eol-badge-critical")
    if days < 180:
        return ("EOL<6m", "eol-badge-high")
    if days < 365:
        return ("EOL<1y", "eol-badge-medium")
    # In good shape — suppress the badge
    return ("", "")


# ---------------------------------------------------------------------------
# Package-manager helpers
# ---------------------------------------------------------------------------

def pkg_manager(os_release: dict[str, str]) -> str:
    """Return the canonical package manager for this distro: apt/dnf/yum/apk/zypper/pacman."""
    distro_id = os_release.get("ID", "").lower()
    id_like = os_release.get("ID_LIKE", "").lower()

    if distro_id in ("ubuntu", "debian", "raspbian", "linuxmint", "pop", "elementary",
                     "kali", "parrot", "zorin"):
        return "apt"
    if distro_id in ("fedora", "rhel", "centos", "rocky", "almalinux", "ol", "amzn"):
        # RHEL 8+, Fedora 22+ use dnf; older CentOS/RHEL use yum
        version_id = os_release.get("VERSION_ID", "")
        try:
            major = int(version_id.split(".")[0])
        except (ValueError, IndexError):
            major = 99
        if distro_id == "fedora" and major >= 22:
            return "dnf"
        if distro_id in ("rhel", "centos", "rocky", "almalinux", "ol") and major >= 8:
            return "dnf"
        return "yum"
    if distro_id == "alpine":
        return "apk"
    if distro_id in ("opensuse-leap", "opensuse-tumbleweed", "suse", "sles"):
        return "zypper"
    if distro_id in ("arch", "manjaro", "endeavouros"):
        return "pacman"
    # ID_LIKE fallbacks
    for parent in id_like.split():
        if parent in ("debian", "ubuntu"):
            return "apt"
        if parent in ("rhel", "fedora"):
            return "dnf"
    return "apt"  # safe default for most Linux


def update_cmds(os_release: dict[str, str]) -> list[str]:
    """Return shell commands to apply all available package updates."""
    pm = pkg_manager(os_release)
    if pm == "apt":
        return [
            "sudo apt update",
            "sudo apt upgrade -y",
            "sudo apt autoremove -y",
        ]
    if pm == "dnf":
        return ["sudo dnf upgrade --refresh -y"]
    if pm == "yum":
        return ["sudo yum update -y"]
    if pm == "apk":
        return ["sudo apk update && sudo apk upgrade"]
    if pm == "zypper":
        return ["sudo zypper refresh && sudo zypper update -y"]
    if pm == "pacman":
        return ["sudo pacman -Syu --noconfirm"]
    return ["sudo apt update && sudo apt upgrade -y"]


# ---------------------------------------------------------------------------
# Distro upgrade steps
# ---------------------------------------------------------------------------

def upgrade_steps(info: EolInfo, os_release: dict[str, str]) -> list[str]:
    """Return human-readable, distro-specific upgrade steps for moving to info.successor.

    Returns generic guidance when the distro is unknown or no successor is defined.
    """
    distro_id = info.distro_id.lower()
    current = info.version
    successor = info.successor or "the next supported release"

    # ── Ubuntu in-place upgrade ──────────────────────────────────────────
    if distro_id == "ubuntu":
        return [
            f"# Upgrade Ubuntu {current} → {successor}",
            "sudo apt update && sudo apt upgrade -y",
            "sudo apt install update-manager-core -y",
            f"sudo do-release-upgrade"
            + (" -d" if _is_dev_release(successor) else ""),
            "# After reboot, verify: lsb_release -a",
        ]

    # ── Debian in-place upgrade ──────────────────────────────────────────
    if distro_id in ("debian", "raspbian"):
        codename_map = {
            "10": "buster", "11": "bullseye", "12": "bookworm",
            "13": "trixie", "14": "forky",
        }
        succ_codename = codename_map.get(successor, successor)
        curr_codename = codename_map.get(current, current)
        return [
            f"# Upgrade Debian {current} ({curr_codename}) → {successor} ({succ_codename})",
            "sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y",
            f"sudo sed -i 's/{curr_codename}/{succ_codename}/g' /etc/apt/sources.list",
            f"sudo sed -i 's/{curr_codename}/{succ_codename}/g'"
            " /etc/apt/sources.list.d/*.list 2>/dev/null || true",
            "sudo apt update",
            "sudo apt upgrade -y",
            "sudo apt full-upgrade -y",
            "sudo apt autoremove -y && sudo reboot",
            f"# After reboot, verify: cat /etc/debian_version",
        ]

    # ── RHEL / CentOS → newer stream ────────────────────────────────────
    if distro_id in ("rhel", "centos"):
        return [
            f"# Upgrade {info.pretty} → {distro_id} {successor}",
            "# In-place major-version upgrades require the leapp tool (RHEL) or",
            "# a fresh installation is recommended for CentOS → Stream migrations.",
            "sudo dnf install leapp-upgrade -y  # RHEL only",
            "sudo leapp preupgrade",
            "sudo leapp upgrade",
            "sudo reboot",
            "# Alternatively, back up data and perform a fresh installation of"
            f" {distro_id} {successor}.",
        ]

    # ── Rocky / AlmaLinux ───────────────────────────────────────────────
    if distro_id in ("rocky", "almalinux"):
        return [
            f"# Upgrade {info.pretty} → {distro_id.capitalize()} Linux {successor}",
            "sudo dnf install leapp-upgrade rocky-release-upgrade -y",
            "sudo leapp preupgrade",
            "sudo leapp upgrade",
            "sudo reboot",
            f"# After reboot, verify: cat /etc/os-release",
        ]

    # ── Fedora ───────────────────────────────────────────────────────────
    if distro_id == "fedora":
        return [
            f"# Upgrade Fedora {current} → {successor}",
            "sudo dnf upgrade --refresh -y",
            "sudo dnf install dnf-plugin-system-upgrade -y",
            f"sudo dnf system-upgrade download --releasever={successor} -y",
            "sudo dnf system-upgrade reboot",
            "# After reboot, verify: cat /etc/fedora-release",
        ]

    # ── Alpine ───────────────────────────────────────────────────────────
    if distro_id == "alpine":
        succ_minor = successor  # e.g. "3.21"
        return [
            f"# Upgrade Alpine {current} → {succ_minor}",
            f"sudo sed -i 's/v{current}/v{succ_minor}/g' /etc/apk/repositories",
            "sudo apk update",
            "sudo apk upgrade --available",
            "sudo sync && sudo reboot",
            "# After reboot, verify: cat /etc/alpine-release",
        ]

    # ── openSUSE Leap ────────────────────────────────────────────────────
    if distro_id == "opensuse-leap":
        return [
            f"# Upgrade openSUSE Leap {current} → {successor}",
            "sudo zypper refresh && sudo zypper update -y",
            f"sudo zypper --releasever={successor} dup --allow-vendor-change -y",
            "sudo reboot",
            "# After reboot, verify: cat /etc/os-release",
        ]

    # ── Amazon Linux ─────────────────────────────────────────────────────
    if distro_id == "amzn":
        return [
            f"# Upgrade Amazon Linux {current} → {successor}",
            "# Amazon Linux does not support in-place major upgrades.",
            "# Launch a new instance with Amazon Linux " + successor,
            "# and migrate your workloads.",
            "# See: https://aws.amazon.com/amazon-linux-2/migration-guide/",
        ]

    # ── Generic fallback ─────────────────────────────────────────────────
    return [
        f"# Upgrade {info.pretty} → {successor}",
        "# Check your distribution's official upgrade documentation.",
        f"# Current distro ID: {distro_id}  version: {current}",
        "# Ensure all packages are up-to-date before upgrading:",
        *update_cmds(os_release),
        "# Then follow the official upgrade path for your distribution.",
    ]


def _is_dev_release(version: str) -> bool:
    """True if the version string looks like an unreleased/development release."""
    # Ubuntu dev releases are odd-year .10 or upcoming LTS not yet out
    return False  # conservative — don't add -d flag by default


def lts_upgrade_steps(info: EolInfo, os_release: dict[str, str]) -> list[str]:
    """Return upgrade steps targeting the nearest LTS release (info.next_lts).

    When next_lts equals successor (or next_lts is None), returns an empty list
    — the caller should use upgrade_steps() instead, there is no separate LTS path.

    For Ubuntu STS releases the LTS path involves stepping through the STS first
    (do-release-upgrade hop-by-hop) or jumping directly if do-release-upgrade
    supports it.  We document the direct jump where possible.
    """
    lts_target = info.next_lts
    if not lts_target or lts_target == info.successor:
        return []

    distro_id = info.distro_id.lower()
    current = info.version

    if distro_id == "ubuntu":
        return [
            f"# Option B — jump directly to LTS: Ubuntu {current} → {lts_target}",
            "# Ubuntu's do-release-upgrade only steps one release at a time.",
            "# To reach the LTS directly, upgrade to the next STS first, then",
            "# run do-release-upgrade again from there.",
            f"# Step 1: upgrade to {info.successor} (STS)",
            "sudo apt update && sudo apt upgrade -y",
            "sudo apt install update-manager-core -y",
            "sudo do-release-upgrade",
            f"# Step 2: from {info.successor}, upgrade to {lts_target} (LTS)",
            "sudo do-release-upgrade",
            f"# After reboot, verify: lsb_release -a  (should show {lts_target})",
            f"# LTS releases are supported for 5 years standard + 5 years ESM.",
        ]

    # For other distros that have an LTS concept (currently only Ubuntu does
    # in the way that requires a separate upgrade path), fall back to generic.
    return [
        f"# Option B — upgrade to nearest LTS: {distro_id} {lts_target}",
        f"# Follow the standard upgrade path, targeting version {lts_target}.",
        *upgrade_steps(
            EolInfo(
                distro_id=info.distro_id,
                version=info.version,
                pretty=info.pretty,
                eol_date=info.eol_date,
                lts_eol_date=info.lts_eol_date,
                successor=lts_target,
                support_type=info.support_type,
                next_lts=None,
            ),
            os_release,
        ),
    ]
