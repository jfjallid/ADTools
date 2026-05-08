"""modify: --set / --add / --delete cycles on a created test user.

Also exercises the @file indirection used to load binary attribute
values from disk (the typical use case is nTSecurityDescriptor).
"""

from __future__ import annotations

import os
import tempfile
from typing import Callable

import pytest

from lib.ad import build_user_dn, search_attr
from lib.assertions import assert_call_succeeded, assert_contains
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
    """Create a disposable user and yield (sam, dn)."""
    name = ldaptest_name("modify")
    dn = build_user_dn(name, base_dn)
    # Register cleanup BEFORE attempting creation.
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


def test_modify_set(target: Target, created_user: tuple[str, str]) -> None:
    name, dn = created_user
    result = run([
        "modify",
        *target.common_argv(),
        "--dn", dn,
        "--set", "description=set-by-test",
    ])
    assert_call_succeeded(result)
    assert_contains(result, "Successfully modified")

    desc = search_attr(target, name, "description")
    assert_call_succeeded(desc)
    assert_contains(desc, "set-by-test")


def test_modify_add_then_delete(target: Target, created_user: tuple[str, str]) -> None:
    name, dn = created_user

    add = run([
        "modify",
        *target.common_argv(),
        "--dn", dn,
        "--add", "description=added-value",
    ])
    assert_call_succeeded(add)

    after_add = search_attr(target, name, "description")
    assert_contains(after_add, "added-value")

    rm = run([
        "modify",
        *target.common_argv(),
        "--dn", dn,
        "--delete", "description=added-value",
    ])
    assert_call_succeeded(rm)

    # `description: added-value` no longer present.
    after_del = search_attr(target, name, "description")
    assert "added-value" not in after_del.combined


def test_modify_value_from_file(
    target: Target,
    created_user: tuple[str, str],
) -> None:
    """Value with @-prefix is loaded from disk."""
    name, dn = created_user
    payload = "value-loaded-from-file"
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(payload)
        path = f.name
    try:
        result = run([
            "modify",
            *target.common_argv(),
            "--dn", dn,
            "--set", f"description=@{path}",
        ])
        assert_call_succeeded(result)
        desc = search_attr(target, name, "description")
        assert_contains(desc, payload)
    finally:
        os.unlink(path)
