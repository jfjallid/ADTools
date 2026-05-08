"""Batch-mode `search` coverage against a live DC.

All cases here are read-only and run unconditionally when a target is
configured. They exercise the search action's flag matrix: filter,
preset, scope, attrs, output formats, controls, paging, and the
out-file path.
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from lib.assertions import assert_call_succeeded, assert_contains
from lib.runner import run
from lib.target import Target


def _search(target: Target, *args: str) -> list[str]:
    return ["search", *target.common_argv(), *args]


def test_default_filter_returns_users(target: Target) -> None:
    """Default filter is (&(objectCategory=person)(objectClass=user))."""
    result = run(_search(target, "--attrs", "sAMAccountName", "--no-banner"))
    assert_call_succeeded(result)
    assert_contains(result, "Found")
    # Administrator exists in every domain.
    assert_contains(result, "Administrator")


def test_explicit_filter(target: Target) -> None:
    result = run(_search(
        target,
        "--filter", "(sAMAccountName=Administrator)",
        "--attrs", "sAMAccountName",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    assert_contains(result, "Found 1 entry")


@pytest.mark.parametrize("preset,expected", [
    ("dcs",            "DC01"),                # this lab has DC01
    ("admins",         "Domain Admins"),
    ("computers",      "Computer"),             # objectCategory in DN
    ("machine-accounts", "$"),                  # sAMAccountName ends with $
])
def test_search_preset(target: Target, preset: str, expected: str) -> None:
    result = run(_search(
        target,
        "--preset", preset,
        "--attrs", "sAMAccountName",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    assert_contains(result, expected)


@pytest.mark.parametrize("scope", ["base", "one", "sub"])
def test_search_scope(target: Target, scope: str) -> None:
    """Each scope value is accepted.

    Use the Builtin container as a search base — it has a small, stable
    child set, so the server won't size-limit-exceed regardless of
    scope.
    """
    parts = target.host.split(".")
    dc_parts = [f"DC={part}" for part in parts[1:]]
    dc = ",".join(dc_parts)
    result = run(_search(
        target,
        "--search-base", f"CN=Builtin,{dc}",
        "--scope", scope,
        "--filter", "(objectClass=*)",
        "--attrs", "objectClass",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    assert_contains(result, "Found")


def test_search_attrs_specific(target: Target) -> None:
    result = run(_search(
        target,
        "--filter", "(sAMAccountName=Administrator)",
        "--attrs", "cn,objectSid",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    assert_contains(result, "cn:")
    assert_contains(result, "objectSid:")


def test_search_attrs_all_user_and_operational(target: Target) -> None:
    """`--attrs *,+` returns both user and operational attributes."""
    result = run(_search(
        target,
        "--filter", "(sAMAccountName=Administrator)",
        "--attrs", "*,+",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    # operational attrs include uSNCreated, whenCreated, etc.
    assert_contains(result, "whenCreated")


def test_search_ldif(target: Target) -> None:
    result = run(_search(
        target,
        "--filter", "(sAMAccountName=Administrator)",
        "--attrs", "cn",
        "--ldif",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    assert_contains(result, "version: 1")
    assert_contains(result, "dn: ")
    assert_contains(result, "cn:")


def test_search_json(target: Target) -> None:
    result = run(_search(
        target,
        "--filter", "(sAMAccountName=Administrator)",
        "--attrs", "cn",
        "--json",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert "dn" in parsed[0]
    assert "attributes" in parsed[0]
    assert "cn" in parsed[0]["attributes"]


def test_search_out_file(target: Target) -> None:
    """`--out-file` writes results to disk instead of stdout.

    The tool opens with O_EXCL, so the path must not yet exist.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "out.ldif")
        result = run(_search(
            target,
            "--filter", "(sAMAccountName=Administrator)",
            "--attrs", "cn",
            "--ldif",
            "--out-file", path,
            "--no-banner",
        ))
        assert_call_succeeded(result)
        with open(path) as f:
            contents = f.read()
        assert "version: 1" in contents
        assert "dn: " in contents


def test_search_size_limit(target: Target) -> None:
    """A size limit large enough for the match passes through cleanly.

    With server-side size limit < result count, AD returns LDAP code 4
    (Size Limit Exceeded) which the tool surfaces as an error — that's
    a separate failure mode, not what this test cares about. We assert
    the limit flag is plumbed through correctly when it doesn't trip.
    """
    result = run(_search(
        target,
        "--filter", "(sAMAccountName=Administrator)",
        "--attrs", "sAMAccountName",
        "--size-limit", "10",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    assert_contains(result, "Found 1 entry")


def test_search_paging(target: Target) -> None:
    """`--page-size` exercises the paged-search code path."""
    result = run(_search(
        target,
        "--filter", "(objectClass=user)",
        "--attrs", "sAMAccountName",
        "--page-size", "1",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    assert_contains(result, "Found")


def test_search_no_banner_suppresses_request_block(target: Target) -> None:
    """Banner is on by default and lists the effective request."""
    with_banner = run(_search(
        target,
        "--filter", "(sAMAccountName=Administrator)",
        "--attrs", "cn",
    ))
    without_banner = run(_search(
        target,
        "--filter", "(sAMAccountName=Administrator)",
        "--attrs", "cn",
        "--no-banner",
    ))
    assert_call_succeeded(with_banner)
    assert_call_succeeded(without_banner)
    # Banner emits "---- effective search request ----" with lowercase
    # field names; --no-banner suppresses that whole block.
    assert "effective search request" in with_banner.combined
    assert "effective search request" not in without_banner.combined


def test_search_show_deleted_control(target: Target) -> None:
    """`--control show-deleted` is accepted; result set is best-effort."""
    result = run(_search(
        target,
        "--filter", "(isDeleted=TRUE)",
        "--attrs", "sAMAccountName",
        "--scope", "sub",
        "--control", "show-deleted",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    # Tombstone container may be empty; assert the tool didn't reject the control.
    assert "Found" in result.combined
