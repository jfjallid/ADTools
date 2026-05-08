"""Live-target connection details, loaded from LDAPTOOL_* env vars.

Tier-2/3 tests skip when required vars are missing, so a tester with
only some lab credentials still gets useful output.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Target:
    host: str
    user: str
    password: str
    domain: str
    dc_ip: Optional[str]
    dns_host: Optional[str]
    nthash: Optional[str]
    aes_key: Optional[str]
    base_dn: Optional[str]

    def common_argv(self) -> list[str]:
        """Connection flags that every batch test needs.

        Includes --host/--user/--pass/--domain plus any optional
        connectivity overrides (--dc-ip, --dns-host).
        """
        argv = [
            "--host",
            self.host,
            "--user",
            self.user,
            "--pass",
            self.password,
            "--domain",
            self.domain,
        ]
        if self.dc_ip:
            argv.extend(["--dc-ip", self.dc_ip])
        if self.dns_host:
            argv.extend(["--dns-host", self.dns_host])
        return argv

    def conn_argv(self) -> list[str]:
        """Connection flags WITHOUT credentials (each caller adds its own).

        Used by the auth-matrix tier where the credential variant is the
        thing under test.
        """
        argv = ["--host", self.host]
        if self.dc_ip:
            argv.extend(["--dc-ip", self.dc_ip])
        if self.dns_host:
            argv.extend(["--dns-host", self.dns_host])
        return argv


_REQUIRED = ("LDAPTOOL_HOST", "LDAPTOOL_USER", "LDAPTOOL_PASS", "LDAPTOOL_DOMAIN")


def load_target() -> Optional[Target]:
    """Return a Target if all required env vars are set, else None."""
    missing = [name for name in _REQUIRED if not os.environ.get(name)]
    if missing:
        return None
    return Target(
        host=os.environ["LDAPTOOL_HOST"],
        user=os.environ["LDAPTOOL_USER"],
        password=os.environ["LDAPTOOL_PASS"],
        domain=os.environ["LDAPTOOL_DOMAIN"],
        dc_ip=os.environ.get("LDAPTOOL_DC_IP"),
        dns_host=os.environ.get("LDAPTOOL_DNS_HOST"),
        nthash=os.environ.get("LDAPTOOL_NTHASH"),
        aes_key=os.environ.get("LDAPTOOL_AES_KEY"),
        base_dn=os.environ.get("LDAPTOOL_BASE_DN"),
    )


def missing_required_message() -> str:
    return (
        "tier-2/3 tests need LDAPTOOL_HOST, LDAPTOOL_USER, LDAPTOOL_PASS, "
        "LDAPTOOL_DOMAIN — set these to point the suite at a lab DC"
    )
