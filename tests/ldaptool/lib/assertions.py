"""Assertion helpers that produce readable failure messages."""

from __future__ import annotations

from .runner import Result


def assert_contains(result: Result, needle: str) -> None:
    if needle in result.combined:
        return
    raise AssertionError(
        f"expected substring not found.\nneedle: {needle!r}\n{result!r}"
    )


def assert_not_contains(result: Result, needle: str) -> None:
    if needle not in result.combined:
        return
    raise AssertionError(
        f"unexpected substring present.\nneedle: {needle!r}\n{result!r}"
    )


def assert_no_connection_attempted(result: Result) -> None:
    """Tier-1 validation: the run must not have reached the network."""
    for marker in (
        "dial tcp",
        "connection refused",
        "i/o timeout",
        "Login failed",
        "Successfully bound",
        "RootDSE query failed",
        "could not detect base DN",
    ):
        if marker in result.combined:
            raise AssertionError(
                f"connection attempt leaked through validation: {marker!r}\n{result!r}"
            )


# Substrings that indicate the binary failed to talk to the target. A
# successful tier-2 invocation must not contain any of these.
_RUNTIME_ERROR_MARKERS = (
    "[Critical]",
    "Failed to bind",
    "connect failed",
    "could not detect base DN",
    "STATUS_LOGON_FAILURE",
    "STATUS_ACCESS_DENIED",
)


def assert_call_succeeded(result: Result) -> None:
    """Tier-2 sanity check: nothing in the output looks like a failure."""
    for marker in _RUNTIME_ERROR_MARKERS:
        if marker in result.combined:
            raise AssertionError(
                f"runtime error in output: {marker!r}\n{result!r}"
            )
    if result.exit_code != 0:
        raise AssertionError(
            f"binary exited with code {result.exit_code} (expected 0)\n{result!r}"
        )
