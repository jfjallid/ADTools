"""rbcd: add / list / remove / clear cycle.

Uses two disposable users — a target (the resource being delegated to)
and a trustee (the one allowed to delegate). RBCD writes a binary
SECURITY_DESCRIPTOR to msDS-AllowedToActOnBehalfOfOtherIdentity.
"""

from __future__ import annotations

import re
from typing import Callable

import pytest

from lib.ad import build_user_dn, search_attr
from lib.assertions import assert_call_succeeded, assert_contains, assert_not_contains
from lib.runner import run, run_quiet
from lib.target import Target

pytestmark = pytest.mark.destructive


def _mk_user(
    target: Target,
    base_dn: str,
    name: str,
    request: pytest.FixtureRequest,
) -> str:
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: run_quiet([
        "delete-object", *target.common_argv(), "--dn", dn,
    ]))
    result = run([
        "create-user",
        *target.common_argv(),
        "--cn", name,
        "--sam", name,
    ])
    assert_call_succeeded(result)
    return dn


@pytest.fixture
def rbcd_pair(
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> tuple[str, str]:
    """Returns (target_sam, trustee_sam) — both ldaptest_* users."""
    target_name = ldaptest_name("rbcdtarget")
    trustee_name = ldaptest_name("rbcdtrustee")
    _mk_user(target, base_dn, target_name, request)
    _mk_user(target, base_dn, trustee_name, request)
    return target_name, trustee_name


def _trustee_sid(target: Target, sam: str) -> str:
    """Read objectSid (base64 in human format) for a sAMAccountName.

    The tool prints `objectSid: S-1-5-...` decoded form, so just regex it.
    """
    result = run([
        "search",
        *target.common_argv(),
        "--filter", f"(sAMAccountName={sam})",
        "--attrs", "objectSid",
        "--no-banner",
    ])
    assert_call_succeeded(result)
    m = re.search(r"objectSid:\s*(S-1-\S+)", result.combined)
    assert m, f"could not find objectSid for {sam!r}: {result!r}"
    return m.group(1)


def test_rbcd_add_list_remove_clear(
    target: Target,
    rbcd_pair: tuple[str, str],
) -> None:
    target_sam, trustee_sam = rbcd_pair

    # Add by sAMAccountName.
    add = run([
        "rbcd", *target.common_argv(),
        "--action", "add",
        "--target", target_sam,
        "--trustee", trustee_sam,
    ])
    assert_call_succeeded(add)

    # List shows the trustee's SID.
    listed = run([
        "rbcd", *target.common_argv(),
        "--action", "list",
        "--target", target_sam,
    ])
    assert_call_succeeded(listed)
    trustee_sid = _trustee_sid(target, trustee_sam)
    assert_contains(listed, trustee_sid)

    # Remove by SID (alternate input form).
    rm = run([
        "rbcd", *target.common_argv(),
        "--action", "remove",
        "--target", target_sam,
        "--trustee", trustee_sid,
    ])
    assert_call_succeeded(rm)

    listed_after_rm = run([
        "rbcd", *target.common_argv(),
        "--action", "list",
        "--target", target_sam,
    ])
    assert_call_succeeded(listed_after_rm)
    assert_not_contains(listed_after_rm, trustee_sid)

    # Re-add then clear nukes the whole attribute.
    run([
        "rbcd", *target.common_argv(),
        "--action", "add",
        "--target", target_sam,
        "--trustee", trustee_sam,
    ])
    clear = run([
        "rbcd", *target.common_argv(),
        "--action", "clear",
        "--target", target_sam,
    ])
    assert_call_succeeded(clear)
