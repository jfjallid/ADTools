"""owner: action-specific validation that fires before any connection.

`owner` validates its flags in Run() *before* dialing (mirroring dacl/access).
We pass a bogus --host so the run clears main.go's host gate but never reaches
the network; assert_no_connection_attempted proves validation short-circuited
first.
"""

from __future__ import annotations

import pytest

from lib.assertions import assert_contains, assert_no_connection_attempted
from lib.runner import run

pytestmark = pytest.mark.validation


# A host that gets past the "--host is required" gate but resolves nowhere.
_BOGUS_CONN = ["--host", "ldaptest.invalid", "--no-pass", "--domain", "d", "--user", "u"]


def test_set_requires_owner() -> None:
    result = run(["owner", "--action", "set", "--target", "foo", *_BOGUS_CONN])
    assert_contains(result, "--owner is required")
    assert_no_connection_attempted(result)


@pytest.mark.parametrize("action", ["backup", "restore"])
def test_backup_restore_require_file(action: str) -> None:
    result = run(["owner", "--action", action, "--target", "foo", *_BOGUS_CONN])
    assert_contains(result, "--file is required")
    assert_no_connection_attempted(result)


def test_unknown_action_rejected() -> None:
    result = run(["owner", "--action", "bogus", "--target", "foo", *_BOGUS_CONN])
    assert_contains(result, "unknown --action")
    assert_no_connection_attempted(result)
