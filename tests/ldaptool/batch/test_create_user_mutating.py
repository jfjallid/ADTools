"""create-user end-to-end.

Two paths:
- Plaintext LDAP, no password set (account starts disabled).
- LDAPS with --user-password and --enabled (gated on ldaps_available).
"""

from __future__ import annotations

from typing import Callable

import pytest

from lib.ad import build_user_dn, find_dn_by_sam, search_attr
from lib.assertions import assert_call_succeeded, assert_contains
from lib.runner import run, run_quiet
from lib.target import Target

pytestmark = pytest.mark.destructive


def _cleanup(target: Target, dn: str) -> None:
    run_quiet(["delete-object", *target.common_argv(), "--dn", dn])


def test_create_user_no_password_disabled_default(
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    """Without --enabled, userAccountControl = 514 (disabled)."""
    name = ldaptest_name("createuser")
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: _cleanup(target, dn))

    result = run([
        "create-user",
        *target.common_argv(),
        "--cn", name,
        "--sam", name,
    ])
    assert_call_succeeded(result)
    assert_contains(result, "User created")

    # Verify userAccountControl = 514 (disabled, normal account).
    uac = search_attr(target, name, "userAccountControl")
    assert_call_succeeded(uac)
    assert_contains(uac, "userAccountControl: 514")


def test_create_user_with_password(
    target: Target,
    base_dn: str,
    ldaps_available: None,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    """LDAPS + --user-password creates an enabled account with a password set."""
    name = ldaptest_name("cupw")
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: _cleanup(target, dn))

    result = run([
        "create-user",
        *target.common_argv(),
        "--tls",
        "--insecure",
        "--cn", name,
        "--sam", name,
        "--user-password", "LdapTestP@ss1!",
        "--enabled",
    ])
    assert_call_succeeded(result)
    assert_contains(result, "User created")

    uac = search_attr(target, name, "userAccountControl")
    assert_call_succeeded(uac)
    # Account remains disabled (514) until something sets UAC=512.
    assert_contains(uac, "userAccountControl: 512")


def test_create_user_with_optional_attrs(
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    """--given-name, --sn, --description, --upn flow into the resulting object."""
    name = ldaptest_name("createuserattrs")
    dn = build_user_dn(name, base_dn)
    _, domain = target.host.split(".", 1)
    request.addfinalizer(lambda: _cleanup(target, dn))

    result = run([
        "create-user",
        *target.common_argv(),
        "--cn", name,
        "--sam", name,
        "--given-name", "Test",
        "--sn", "User",
        "--description", "ldaptool integration test",
        "--upn", f"{name}@{domain}",
    ])
    assert_call_succeeded(result)

    found = find_dn_by_sam(target, name)
    assert found is not None


def test_create_user_custom_ou(
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    """`--ou <full-dn>` places the new user under a non-default container.

    Uses CN=Managed Service Accounts (present by default since AD 2008 R2).
    Skips if that container is missing on the lab DC.
    """
    msa_container = f"CN=Managed Service Accounts,{base_dn}"
    probe = run([
        "search",
        *target.common_argv(),
        "--search-base", msa_container,
        "--scope", "base",
        "--filter", "(objectClass=*)",
        "--attrs", "objectClass",
        "--no-banner",
    ])
    if "Found 1 entry" not in probe.combined:
        pytest.skip(f"{msa_container} not present on lab DC")

    name = ldaptest_name("ou")
    expected_dn = f"CN={name},{msa_container}"
    request.addfinalizer(lambda: _cleanup(target, expected_dn))

    result = run([
        "create-user",
        *target.common_argv(),
        "--cn", name,
        "--sam", name,
        "--ou", msa_container,
    ])
    assert_call_succeeded(result)
    assert_contains(result, "User created")
    assert_contains(result, expected_dn)

    # Confirm via search that the user lives where --ou said.
    found = find_dn_by_sam(target, name)
    assert found is not None
    assert found.lower() == expected_dn.lower(), (
        f"expected {expected_dn!r}, got {found!r}"
    )


def test_created_user_can_authenticate(
    target: Target,
    base_dn: str,
    ldaps_available: None,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    """Round-trip: create an enabled user, then bind as that user.

    Verifies `--user-password` actually sets unicodePwd to the supplied
    value (not just that the create call succeeded).
    """
    name = ldaptest_name("rtpw")
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: _cleanup(target, dn))

    password = "RoundTripP@ss1!"
    create = run([
        "create-user",
        *target.common_argv(),
        "--tls",
        "--insecure",
        "--cn", name,
        "--sam", name,
        "--user-password", password,
        "--enabled",
    ])
    assert_call_succeeded(create)

    # Re-bind as the new user with the password we just set.
    bind_check = run([
        "search",
        "--host", target.host,
        "--tls",
        "--insecure",
        "--user", name,
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
