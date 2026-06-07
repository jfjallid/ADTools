"""Validation tests for set-password (Tier 1, no network)."""

import pytest

from lib.runner import run
from lib.assertions import assert_contains, assert_no_connection_attempted


pytestmark = pytest.mark.validation


def test_help_lists_options() -> None:
    result = run(["set-password", "--help"])
    assert result.exit_code == 0
    assert_contains(result, "Set-password options")
    assert_no_connection_attempted(result)


def test_missing_target_errors_without_connecting() -> None:
    result = run(["set-password", "--host", "dc.example.invalid", "--tls"])
    assert result.exit_code != 0
    assert_contains(result, "--target is required")
    assert_no_connection_attempted(result)


def test_requires_confidential_channel() -> None:
    # --sasl none with no TLS is a non-confidential channel and must be
    # rejected before any connection. (Plain NTLM defaults to sealing, which
    # IS confidential, so it is intentionally allowed.)
    result = run(
        [
            "set-password",
            "--host",
            "dc.example.invalid",
            "--sasl",
            "none",
            "--target",
            "victim",
            "--new-password",
            "x",
        ]
    )
    assert result.exit_code != 0
    assert_contains(result, "confidential connection")
    assert_no_connection_attempted(result)
