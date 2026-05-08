"""End-to-end test for the new `delete-object` subcommand.

Creates a user, verifies it exists, deletes it via delete-object,
and verifies it's gone. The fixture-based cleanup pattern is the
template for every other mutating test in this tier.
"""

from __future__ import annotations

from typing import Callable

import pytest

from lib.ad import build_user_dn, find_dn_by_sam
from lib.assertions import assert_call_succeeded, assert_contains
from lib.runner import run, run_quiet
from lib.target import Target

pytestmark = pytest.mark.destructive


def test_delete_object_round_trip(
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    name = ldaptest_name("del")
    expected_dn = build_user_dn(name, base_dn)

    # Defensive cleanup: even if the create succeeds and the explicit
    # delete fails partway through, this finalizer reaps any orphan.
    request.addfinalizer(lambda: run_quiet([
        "delete-object", *target.common_argv(), "--dn", expected_dn,
    ]))

    create = run([
        "create-user",
        *target.common_argv(),
        "--cn", name,
        "--sam", name,
    ])
    assert_call_succeeded(create)
    assert_contains(create, "User created")
    assert_contains(create, expected_dn)

    # Confirm presence via a search before deleting.
    found = find_dn_by_sam(target, name)
    assert found is not None
    assert found.lower() == expected_dn.lower()

    # The action under test.
    delete = run([
        "delete-object",
        *target.common_argv(),
        "--dn", expected_dn,
    ])
    assert_call_succeeded(delete)
    assert_contains(delete, "Deleted:")
    assert_contains(delete, expected_dn)

    # Confirm absence.
    assert find_dn_by_sam(target, name) is None


def test_delete_object_missing_dn_rejects(target: Target) -> None:
    """`delete-object` without --dn fails after the bind succeeds."""
    result = run(["delete-object", *target.common_argv()])
    assert result.exit_code != 0
    assert_contains(result, "--dn is required")


def test_delete_object_nonexistent_dn_errors(
    target: Target,
    base_dn: str,
) -> None:
    """Deleting a DN that doesn't exist surfaces the LDAP error."""
    bogus = f"CN=ldaptest_does_not_exist_xyz,CN=Users,{base_dn}"
    result = run([
        "delete-object",
        *target.common_argv(),
        "--dn", bogus,
    ])
    assert result.exit_code != 0
    # AD returns "No Such Object" / LDAP code 32 for missing DNs.
    assert "delete failed" in result.combined.lower() or "no such" in result.combined.lower()
