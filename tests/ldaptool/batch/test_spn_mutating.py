"""spn: add / remove / replace cycle on a disposable user."""

from __future__ import annotations

from typing import Callable

import pytest

from lib.ad import build_user_dn, search_attr
from lib.assertions import assert_call_succeeded, assert_contains, assert_not_contains
from lib.runner import run, run_quiet
from lib.target import Target

pytestmark = pytest.mark.destructive


@pytest.fixture
def created_user(
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> tuple[str, str]:
    name = ldaptest_name("spn")
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


def test_spn_add_remove(target: Target, created_user: tuple[str, str]) -> None:
    name, dn = created_user
    spn = "HTTP/ldaptest.example.com"

    add = run([
        "spn",
        *target.common_argv(),
        "--dn", dn,
        "--add", spn,
    ])
    assert_call_succeeded(add)
    assert_contains(add, "SPN updated")

    after_add = search_attr(target, name, "servicePrincipalName")
    assert_contains(after_add, spn)

    rm = run([
        "spn",
        *target.common_argv(),
        "--dn", dn,
        "--remove", spn,
    ])
    assert_call_succeeded(rm)

    after_rm = search_attr(target, name, "servicePrincipalName")
    assert_not_contains(after_rm, spn)


def test_spn_replace(target: Target, created_user: tuple[str, str]) -> None:
    name, dn = created_user

    # Seed two SPNs, then replace with one.
    seed = run([
        "spn", *target.common_argv(), "--dn", dn,
        "--add", "HTTP/seed1.example.com",
        "--add", "HTTP/seed2.example.com",
    ])
    assert_call_succeeded(seed)

    replace = run([
        "spn", *target.common_argv(), "--dn", dn,
        "--replace", "HTTP/replaced.example.com",
    ])
    assert_call_succeeded(replace)

    after = search_attr(target, name, "servicePrincipalName")
    assert_contains(after, "HTTP/replaced.example.com")
    assert_not_contains(after, "HTTP/seed1.example.com")
    assert_not_contains(after, "HTTP/seed2.example.com")
