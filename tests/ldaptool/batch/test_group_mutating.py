"""group: add / remove member cycles.

Uses the built-in "Guests" group (always present in any AD domain) as
the target, and a disposable test user as the member.
"""

from __future__ import annotations

from typing import Callable

import pytest

from lib.ad import build_computer_dn, build_user_dn, search_attr
from lib.assertions import assert_call_succeeded, assert_contains, assert_not_contains
from lib.runner import run, run_quiet
from lib.target import Target

pytestmark = pytest.mark.destructive


@pytest.fixture
def member_user(
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> tuple[str, str]:
    name = ldaptest_name("group")
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
    return name, dn


def test_group_add_then_remove(target: Target, member_user: tuple[str, str]) -> None:
    name, _ = member_user
    group = "Guests"  # well-known, always present

    add = run([
        "group",
        *target.common_argv(),
        "--action", "add",
        "--group", group,
        "--member", name,
    ])
    assert_call_succeeded(add)

    after_add = search_attr(target, "Guests", "member")
    assert_contains(after_add, name)

    rm = run([
        "group",
        *target.common_argv(),
        "--action", "remove",
        "--group", group,
        "--member", name,
    ])
    assert_call_succeeded(rm)

    after_rm = search_attr(target, "Guests", "member")
    assert_not_contains(after_rm, name)


@pytest.mark.parametrize("with_dollar_suffix", [True, False])
def test_group_computer_member(
    target: Target,
    base_dn: str,
    ldaps_available: None,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
    with_dollar_suffix: bool,
) -> None:
    """Computer accounts can be added as group members both with and
    without the trailing `$` (the tool normalises the form).

    Tests the "Guests" group (well-known) — same as the user variant —
    but uses a freshly created computer account instead of a user.
    """
    cn = ldaptest_name("gc" if with_dollar_suffix else "gnc")
    computer_dn = build_computer_dn(cn, base_dn)
    request.addfinalizer(lambda: run_quiet([
        "delete-object", *target.common_argv(), "--dn", computer_dn,
    ]))
    create = run([
        "create-computer",
        *target.common_argv(),
        "--tls", "--insecure",
        "--cn", cn,
    ])
    assert_call_succeeded(create)

    member_arg = (cn + "$") if with_dollar_suffix else cn
    add = run([
        "group",
        *target.common_argv(),
        "--action", "add",
        "--group", "Guests",
        "--member", member_arg,
    ])
    assert_call_succeeded(add)

    after_add = search_attr(target, "Guests", "member")
    # Either casing matches; the DN holds the upper-cased computer CN.
    assert cn.upper() in after_add.combined.upper(), after_add

    rm = run([
        "group",
        *target.common_argv(),
        "--action", "remove",
        "--group", "Guests",
        "--member", member_arg,
    ])
    assert_call_succeeded(rm)

    after_rm = search_attr(target, "Guests", "member")
    assert cn.upper() not in after_rm.combined.upper(), after_rm
