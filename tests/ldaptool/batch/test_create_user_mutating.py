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
