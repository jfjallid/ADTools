"""Validation rules that fire before any network attempt.

The tool checks `--ldif` + `--json` mutual exclusion (and `--simple` /
`--anonymous` / `--kerberos` overlap) before opening a connection.
These tests pass `--host` (so we get past the host gate) but use a
nonexistent host; if the validation does its job, we never reach DNS.
"""

from __future__ import annotations

import pytest

from lib.assertions import assert_contains, assert_no_connection_attempted
from lib.runner import run

pytestmark = pytest.mark.validation


_BOGUS_CONN = ["--host", "ldaptest.invalid", "--no-pass"]


def test_ldif_and_json_are_mutually_exclusive() -> None:
    result = run(["search", *_BOGUS_CONN, "--ldif", "--json"])
    assert_contains(result, "mutually exclusive")
    # The check fires before the dialer; no DNS lookup should leak.
    assert_no_connection_attempted(result)


def test_invalid_scope_rejected() -> None:
    """`--scope nonsense` is parsed but rejected before opening a connection."""
    result = run(["search", *_BOGUS_CONN, "--scope", "nonsense"])
    assert_contains(result, "scope")
    assert_no_connection_attempted(result)


def test_unknown_preset_rejected() -> None:
    result = run(["search", *_BOGUS_CONN, "--preset", "definitely-not-a-preset"])
    assert_contains(result, "preset")
    assert_no_connection_attempted(result)


# Note: shadow-credentials, rbcd, group, spn, modify, delete-object validate
# their action-specific flags AFTER makeConnection succeeds. Those checks
# are exercised in tier 2 against the live DC, not here.
