"""Mutating tests for set-password inside the interactive shell (Tier 3)."""

import pytest

from lib.runner import run
from lib.shell import LdapShell
from lib.ad import build_user_dn, delete_dn
from lib.target import Target


pytestmark = pytest.mark.destructive


def _cleanup(target: Target, dn: str) -> None:
    delete_dn(target, dn)


def test_setpassword_in_shell(
    target: Target,
    base_dn: str,
    ldaps_available: None,
    ldaptest_name,
    request: pytest.FixtureRequest,
) -> None:
    name = ldaptest_name("shspw")
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: _cleanup(target, dn))

    created = run(
        [
            "create-user",
            *target.common_argv(),
            "--tls",
            "--insecure",
            "--cn",
            name,
            "--sam",
            name,
            "--user-password",
            "LdapTestP@ss1!",
            "--enabled",
        ]
    )
    assert created.exit_code == 0, created.combined

    # set-password needs a confidential channel, so drive a TLS-connected shell.
    proc = LdapShell(target, extra_args=["--tls", "--insecure"])
    request.addfinalizer(proc.close)

    out = proc.cmd(f"setpassword -reset -target {name} -newpass ShellP@ss2!")
    assert "Password reset for" in out, out
    assert dn.lower() in out.lower(), out
