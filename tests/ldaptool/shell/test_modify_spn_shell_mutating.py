"""modify / spn / group / rbcd in the REPL."""

from __future__ import annotations

from typing import Callable

import pytest

from lib.ad import build_user_dn
from lib.runner import run, run_quiet
from lib.shell import LdapShell
from lib.target import Target

pytestmark = pytest.mark.destructive


def _create(target: Target, name: str) -> None:
    """Pre-create a victim user via batch mode (so the shell test focuses
    only on the action under test, not on createuser plus the action)."""
    run([
        "create-user",
        *target.common_argv(),
        "--cn", name,
        "--sam", name,
    ])


def _cleanup(target: Target, dn: str) -> None:
    run_quiet(["delete-object", *target.common_argv(), "--dn", dn])


@pytest.fixture
def victim(
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> tuple[str, str]:
    name = ldaptest_name("sm")
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: _cleanup(target, dn))
    _create(target, name)
    return name, dn


def test_modify_in_shell(shell: LdapShell, victim: tuple[str, str]) -> None:
    _name, dn = victim
    out = shell.cmd(f"modify -dn {dn} -set description=shell-set")
    assert "Successfully modified" in out, out


def test_spn_in_shell(shell: LdapShell, victim: tuple[str, str]) -> None:
    _name, dn = victim
    out = shell.cmd(f"spn -dn {dn} -add HTTP/shelltest.example.com")
    assert "SPN updated" in out, out


def test_group_in_shell(shell: LdapShell, victim: tuple[str, str]) -> None:
    name, _ = victim
    out_add = shell.cmd(f"group -action add -group Guests -member {name}")
    assert "Error" not in out_add, out_add
    out_rm = shell.cmd(f"group -action remove -group Guests -member {name}")
    assert "Error" not in out_rm, out_rm


def test_rbcd_in_shell(
    shell: LdapShell,
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    """rbcd needs both target and trustee accounts."""
    target_name = ldaptest_name("srt")
    trustee_name = ldaptest_name("srtt")
    request.addfinalizer(lambda: _cleanup(target, build_user_dn(trustee_name, base_dn)))
    request.addfinalizer(lambda: _cleanup(target, build_user_dn(target_name, base_dn)))
    _create(target, target_name)
    _create(target, trustee_name)

    out_add = shell.cmd(
        f"rbcd -action add -target {target_name} -trustee {trustee_name}"
    )
    assert "Error" not in out_add, out_add

    out_list = shell.cmd(f"rbcd -action list -target {target_name}")
    # Just sanity-check the list runs without error.
    assert "Error" not in out_list, out_list

    out_clear = shell.cmd(f"rbcd -action clear -target {target_name}")
    assert "Error" not in out_clear, out_clear


def test_laps_in_shell(shell: LdapShell) -> None:
    """`laps` runs without args; output may be empty if no LAPS users in lab."""
    out = shell.cmd("laps")
    # Whatever the lab returns, the call should not error out.
    assert "Error" not in out, out
