"""modify / spn / group / rbcd in the REPL."""

from __future__ import annotations

import os
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


def test_spn_replace_then_remove_in_shell(
    shell: LdapShell, victim: tuple[str, str],
) -> None:
    """`spn -replace` overwrites; `spn -remove` deletes a single value.

    The batch-mode test covers add/remove/replace cycles; this exercises
    the same dispatcher in the REPL since spn_shell.go has its own arg
    parser.
    """
    name, dn = victim

    seed = shell.cmd(f"spn -dn {dn} -add HTTP/seed.example.com")
    assert "SPN updated" in seed, seed

    replaced = shell.cmd(f"spn -dn {dn} -replace HOST/{name}")
    assert "SPN updated" in replaced, replaced

    after = shell.cmd(
        f"search -filter (sAMAccountName={name}) -attrs servicePrincipalName -no-banner"
    )
    assert "seed.example.com" not in after, after
    assert f"HOST/{name}" in after, after

    removed = shell.cmd(f"spn -dn {dn} -remove HOST/{name}")
    assert "SPN updated" in removed, removed

    after_rm = shell.cmd(
        f"search -filter (sAMAccountName={name}) -attrs servicePrincipalName -no-banner"
    )
    assert f"HOST/{name}" not in after_rm, after_rm


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


def test_laps_specific_target_in_shell(shell: LdapShell) -> None:
    """`laps -target <sam>` narrows to a single computer.

    LAPS attrs may not be set on the lab DC, so we accept either a
    result block or the "no readable" diagnostic — but no Error.
    """
    out = shell.cmd("laps -target DC01")
    assert "Error" not in out, out


def test_shadowcreds_add_list_clear_in_shell(
    target: Target,
    base_dn: str,
    ldaps_available: None,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
    tmp_path,
) -> None:
    """The `shadowcreds` REPL command mirrors the batch-mode add→list→clear flow.

    Spawns its own LDAPS-bound shell — `shadowcreds add` writes
    msDS-KeyCredentialLink and that requires a confidential channel.
    """
    name = ldaptest_name("ssh")
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: _cleanup(target, dn))
    _create(target, name)

    pfx_path = str(tmp_path / f"{name}.pfx")
    sh = LdapShell(target, extra_args=["--tls", "--insecure"])
    try:
        added = sh.cmd(f"shadowcreds -action add -target {name} -out {pfx_path}")
        assert "Shadow credential added" in added, added
        assert os.path.exists(pfx_path), f"PFX not written at {pfx_path}"

        listed = sh.cmd(f"shadowcreds -action list -target {name}")
        # Listing must not error; presence of a Device ID confirms the add.
        assert "Error" not in listed, listed
        assert "Device ID" in listed, listed

        cleared = sh.cmd(f"shadowcreds -action clear -target {name}")
        assert "Error" not in cleared, cleared
    finally:
        sh.close()
