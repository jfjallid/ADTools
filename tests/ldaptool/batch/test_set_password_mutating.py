"""Mutating tests for set-password (Tier 2, destructive).

Gated on a reachable LDAPS endpoint because AD only writes unicodePwd over a
confidential channel.
"""

import pytest

from lib.runner import run
from lib.target import Target
from lib.ad import build_user_dn, delete_dn
from lib.assertions import assert_call_succeeded, assert_contains


pytestmark = pytest.mark.destructive


def _cleanup(target: Target, dn: str) -> None:
    delete_dn(target, dn)


def _create_user(target: Target, name: str, password: str):
    return run(
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
            password,
            "--enabled",
        ]
    )


def test_admin_reset(
    target: Target,
    base_dn: str,
    ldaps_available: None,
    ldaptest_name,
    request: pytest.FixtureRequest,
) -> None:
    name = ldaptest_name("sprst")
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: _cleanup(target, dn))

    created = _create_user(target, name, "LdapTestP@ss1!")
    assert_call_succeeded(created)

    result = run(
        [
            "set-password",
            *target.common_argv(),
            "--tls",
            "--insecure",
            "--reset",
            "--target",
            name,
            "--new-password",
            "ResetP@ss2!",
        ]
    )
    assert_call_succeeded(result)
    assert_contains(result, "Password reset for")


def test_self_service_change(
    target: Target,
    base_dn: str,
    ldaps_available: None,
    ldaptest_name,
    request: pytest.FixtureRequest,
) -> None:
    name = ldaptest_name("spchg")
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: _cleanup(target, dn))

    created = _create_user(target, name, "LdapTestP@ss1!")
    assert_call_succeeded(created)

    # Delete(old)+Add(new): AD validates the supplied old value against the
    # current password regardless of the binding identity.
    result = run(
        [
            "set-password",
            *target.common_argv(),
            "--tls",
            "--insecure",
            "--target",
            name,
            "--old-password",
            "LdapTestP@ss1!",
            "--new-password",
            "ChangedP@ss3!",
        ]
    )
    assert_call_succeeded(result)
    assert_contains(result, "Password changed for")
