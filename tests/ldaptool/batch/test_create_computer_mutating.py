"""create-computer end-to-end (always over LDAPS — random password is set)."""

from __future__ import annotations

from typing import Callable

import pytest

from lib.ad import build_computer_dn, find_dn_by_sam, search_attr
from lib.assertions import assert_call_succeeded, assert_contains
from lib.runner import run, run_quiet
from lib.target import Target

pytestmark = pytest.mark.destructive


def test_create_computer(
    target: Target,
    base_dn: str,
    ldaps_available: None,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    name = ldaptest_name("createcomp")
    expected_dn = build_computer_dn(name, base_dn)
    request.addfinalizer(lambda: run_quiet([
        "delete-object", *target.common_argv(), "--dn", expected_dn,
    ]))

    result = run([
        "create-computer",
        *target.common_argv(),
        "--tls",
        "--insecure",
        "--cn", name,
    ])
    assert_call_succeeded(result)
    assert_contains(result, "Computer created")

    # sAMAccountName ends with $; UAC includes WORKSTATION_TRUST_ACCOUNT (4096).
    sam = name + "$"
    found = find_dn_by_sam(target, sam)
    assert found is not None, f"computer {sam!r} not found via sAMAccountName lookup"

    uac_result = search_attr(target, sam, "userAccountControl")
    assert_call_succeeded(uac_result)
    assert_contains(uac_result, "userAccountControl: 4096")


def test_create_computer_explicit_password_and_managed_by(
    target: Target,
    base_dn: str,
    ldaps_available: None,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    """`--password` sets the machine password verbatim, `--managed-by` sets managedBy."""
    name = ldaptest_name("ccpw")
    expected_dn = build_computer_dn(name, base_dn)
    request.addfinalizer(lambda: run_quiet([
        "delete-object", *target.common_argv(), "--dn", expected_dn,
    ]))

    manager_dn = f"CN=Administrator,CN=Users,{base_dn}"
    password = "C0mput3rP@ss!Long"

    result = run([
        "create-computer",
        *target.common_argv(),
        "--tls",
        "--insecure",
        "--cn", name,
        "--password", password,
        "--managed-by", manager_dn,
    ])
    assert_call_succeeded(result)
    assert_contains(result, "Computer created")

    sam = name + "$"
    managed_by = search_attr(target, sam, "managedBy")
    assert_call_succeeded(managed_by)
    # AD canonicalises the managedBy DN — match case-insensitively.
    assert manager_dn.lower() in managed_by.combined.lower(), managed_by


def test_created_computer_can_authenticate(
    target: Target,
    base_dn: str,
    ldaps_available: None,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    """Round-trip: create a computer with an explicit password, bind as it."""
    name = ldaptest_name("ccrt")
    expected_dn = build_computer_dn(name, base_dn)
    request.addfinalizer(lambda: run_quiet([
        "delete-object", *target.common_argv(), "--dn", expected_dn,
    ]))

    password = "C0mput3rB1ndP@ss!"
    create = run([
        "create-computer",
        *target.common_argv(),
        "--tls",
        "--insecure",
        "--cn", name,
        "--password", password,
    ])
    assert_call_succeeded(create)

    # Bind as the new computer with the password we just set.
    sam = name + "$"
    bind_check = run([
        "search",
        "--host", target.host,
        "--tls",
        "--insecure",
        "--user", sam,
        "--pass", password,
        "--domain", target.domain,
        *( ["--dc-ip", target.dc_ip] if target.dc_ip else [] ),
        "--scope", "base",
        "--search-base", "",
        "--filter", "(objectClass=*)",
        "--attrs", "dnsHostName",
        "--no-banner",
    ])
    assert_call_succeeded(bind_check)
    assert_contains(bind_check, "Found 1 entry")
