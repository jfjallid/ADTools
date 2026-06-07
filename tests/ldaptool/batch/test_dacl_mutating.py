"""dacl: read / add / remove / backup / restore on an object DACL.

Edits the discretionary ACL of an object's nTSecurityDescriptor. Uses a
disposable victim object and a disposable trustee; grants the trustee a
ResetPassword ACE, confirms it appears, then removes it. Writes are scoped
to the DACL via the SD-flags control (owner/group/SACL untouched).
"""

from __future__ import annotations

import os
import re
from typing import Callable

import pytest

from lib.ad import build_user_dn
from lib.assertions import (
    assert_call_succeeded,
    assert_contains,
    assert_not_contains,
)
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


def _sid_of(target: Target, sam: str) -> str:
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


@pytest.fixture
def dacl_pair(
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> tuple[str, str]:
    """Returns (victim_sam, trustee_sam) — both freshly created users."""
    victim = ldaptest_name("daclv")
    trustee = ldaptest_name("daclt")
    _mk_user(target, base_dn, victim, request)
    _mk_user(target, base_dn, trustee, request)
    return victim, trustee


def test_dacl_read(target: Target, dacl_pair: tuple[str, str]) -> None:
    victim, _ = dacl_pair
    result = run([
        "dacl", *target.common_argv(),
        "--action", "read",
        "--target", victim,
    ])
    assert_call_succeeded(result)
    assert_contains(result, "Owner:")
    assert_contains(result, "ACEs (")


def test_dacl_add_then_remove(target: Target, dacl_pair: tuple[str, str]) -> None:
    victim, trustee = dacl_pair
    trustee_sid = _sid_of(target, trustee)

    add = run([
        "dacl", *target.common_argv(),
        "--action", "add",
        "--target", victim,
        "--trustee", trustee,
        "--rights", "ResetPassword",
    ])
    assert_call_succeeded(add)
    assert_contains(add, "Added")

    after_add = run([
        "dacl", *target.common_argv(),
        "--action", "read",
        "--target", victim,
    ])
    assert_call_succeeded(after_add)
    assert_contains(after_add, trustee_sid)

    rm = run([
        "dacl", *target.common_argv(),
        "--action", "remove",
        "--target", victim,
        "--trustee", trustee,
        "--rights", "ResetPassword",
    ])
    assert_call_succeeded(rm)
    assert_contains(rm, "Removed")

    after_rm = run([
        "dacl", *target.common_argv(),
        "--action", "read",
        "--target", victim,
    ])
    assert_call_succeeded(after_rm)
    assert_not_contains(after_rm, trustee_sid)


def test_dacl_backup_restore(
    target: Target,
    dacl_pair: tuple[str, str],
    tmp_path,
) -> None:
    victim, _ = dacl_pair
    backup_file = str(tmp_path / f"{victim}.sd")

    backup = run([
        "dacl", *target.common_argv(),
        "--action", "backup",
        "--target", victim,
        "--file", backup_file,
    ])
    assert_call_succeeded(backup)
    assert os.path.exists(backup_file), f"backup not written at {backup_file}"

    restore = run([
        "dacl", *target.common_argv(),
        "--action", "restore",
        "--target", victim,
        "--file", backup_file,
    ])
    assert_call_succeeded(restore)
    assert_contains(restore, "Restored")
