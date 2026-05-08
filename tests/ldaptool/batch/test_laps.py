"""`laps` enumerates LAPS-managed local-admin passwords.

The lab DC may not have any LAPS-equipped computers, so the tool
returning "no readable computers" is a valid success outcome — we
assert only that the call succeeded and didn't crash.
"""

from __future__ import annotations

from lib.assertions import assert_call_succeeded
from lib.runner import run
from lib.target import Target


def test_laps_no_target(target: Target) -> None:
    """Without --target, laps enumerates every readable computer."""
    result = run(["laps", *target.common_argv()])
    assert_call_succeeded(result)


def test_laps_specific_target(target: Target) -> None:
    """With --target, laps narrows to a single sAMAccountName.

    The DC is the only guaranteed computer in this lab; LAPS attrs may
    not be set on it, so we accept either a result block or the
    "no readable" diagnostic.
    """
    result = run([
        "laps",
        *target.common_argv(),
        "--target", "DC01",
    ])
    assert_call_succeeded(result)
