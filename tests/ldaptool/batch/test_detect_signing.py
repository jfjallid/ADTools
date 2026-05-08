"""`detect-signing` probes the DC's signing requirement."""

from __future__ import annotations

from lib.assertions import assert_call_succeeded, assert_contains
from lib.runner import run
from lib.target import Target


def test_detect_signing_returns_boolean(target: Target) -> None:
    result = run(["detect-signing", *target.common_argv()])
    assert_call_succeeded(result)
    # Output is "LDAP signing required: true" or "LDAP signing required: false".
    assert_contains(result, "LDAP signing required:")
    combined = result.combined
    assert ("required: true" in combined) or ("required: false" in combined)
