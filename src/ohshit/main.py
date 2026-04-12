from __future__ import annotations

import argparse

from .tui.app import OhShitApp


def run() -> None:
    parser = argparse.ArgumentParser(
        description="Oh-Shit: Home Network Security Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Keyboard shortcuts:
  r   Re-scan all hosts
  s   Re-scan selected host
  e   Export Markdown report to ~/
  q   Quit

Security note: SSH host key checking is disabled for LAN convenience.
Use --strict-host-keys to enable ~/.ssh/known_hosts verification.
""",
    )
    parser.add_argument("--no-ssh", action="store_true", help="Skip SSH collection (discovery only)")
    parser.add_argument("--subnet", metavar="CIDR", help="Override subnet, e.g. 192.168.1.0/24")
    parser.add_argument("--strict-host-keys", action="store_true", help="Verify SSH host keys via known_hosts")
    args = parser.parse_args()

    app = OhShitApp(
        no_ssh=args.no_ssh,
        subnet_override=args.subnet,
        strict_host_keys=args.strict_host_keys,
    )
    app.run()
