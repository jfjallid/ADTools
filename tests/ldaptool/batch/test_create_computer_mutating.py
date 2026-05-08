"""create-computer end-to-end (always over LDAPS — random password is set)."""

from __future__ import annotations

from typing import Callable

import pytest

from lib.ad import build_computer_dn, find_dn_by_sam, search_attr
from lib.assertions import assert_call_succeeded, assert_contains
from lib.runner import run, run_quiet
from lib.target import Target

pytestmark = pytest.mark.destructive


def test_create_computer(
    target: Target,
    base_dn: str,
    ldaps_available: None,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    name = ldaptest_name("createcomp")
    expected_dn = build_computer_dn(name, base_dn)
    request.addfinalizer(lambda: run_quiet([
        "delete-object", *target.common_argv(), "--dn", expected_dn,
    ]))

    result = run([
        "create-computer",
        *target.common_argv(),
        "--tls",
        "--insecure",
        "--cn", name,
    ])
    assert_call_succeeded(result)
    assert_contains(result, "Computer created")

    # sAMAccountName ends with $; UAC includes WORKSTATION_TRUST_ACCOUNT (4096).
    sam = name + "$"
    found = find_dn_by_sam(target, sam)
    assert found is not None, f"computer {sam!r} not found via sAMAccountName lookup"

    uac_result = search_attr(target, sam, "userAccountControl")
    assert_call_succeeded(uac_result)
    assert_contains(uac_result, "userAccountControl: 4096")
