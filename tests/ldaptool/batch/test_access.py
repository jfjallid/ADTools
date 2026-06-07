"""access: compute a principal's effective access to an object.

Read-only (no object creation) — evaluates the well-known Administrator
account against itself, which exists in every domain. Exercises the token
build (own SID + tokenGroups + SELF) and the DACL access-check report.
"""

from __future__ import annotations

from lib.assertions import assert_call_succeeded, assert_contains
from lib.runner import run
from lib.target import Target


def test_access_full_report(target: Target) -> None:
    result = run([
        "access", *target.common_argv(),
        "--target", "Administrator",
        "--principal", "Administrator",
    ])
    assert_call_succeeded(result)
    assert_contains(result, "Effective access for")


def test_access_single_right(target: Target) -> None:
    """The --right form asks about one specific right instead of a full report."""
    result = run([
        "access", *target.common_argv(),
        "--target", "Administrator",
        "--principal", "Administrator",
        "--right", "GenericAll",
    ])
    assert_call_succeeded(result)
    assert_contains(result, "Effective access for")


def test_access_show_token(target: Target) -> None:
    """--show-token prints the expanded SID set used for the check."""
    result = run([
        "access", *target.common_argv(),
        "--target", "Administrator",
        "--principal", "Administrator",
        "--show-token",
    ])
    assert_call_succeeded(result)
    assert_contains(result, "Token (")
