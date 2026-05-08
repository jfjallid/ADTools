"""Top-level argument-parsing tests.

These cover the entry points in main.go before any subcommand handler
runs: the help banner, --version, unknown subcommand, and the missing
--host gate.
"""

from __future__ import annotations

import pytest

from lib.assertions import assert_contains, assert_no_connection_attempted
from lib.runner import run

pytestmark = pytest.mark.validation


def test_no_args_prints_help() -> None:
    result = run([])
    assert result.exit_code == 2
    assert_contains(result, "Usage:")
    assert_contains(result, "Subcommands:")
    assert_contains(result, "search")
    assert_contains(result, "modify")
    assert_contains(result, "delete-object")
    assert_no_connection_attempted(result)


@pytest.mark.parametrize("flag", ["--version", "-v"])
def test_version_prints_version(flag: str) -> None:
    result = run([flag])
    assert result.exit_code == 0
    assert_contains(result, "ldaptool version")
    assert_no_connection_attempted(result)


@pytest.mark.parametrize("flag", ["--help", "-h", "help"])
def test_help_prints_top_level_help(flag: str) -> None:
    result = run([flag])
    assert result.exit_code == 0
    assert_contains(result, "Subcommands:")
    assert_contains(result, "Connection options:")
    assert_no_connection_attempted(result)


def test_unknown_subcommand_rejected() -> None:
    result = run(["totally-not-a-subcommand"])
    assert result.exit_code == 2
    assert_contains(result, "Unknown subcommand:")
    assert_contains(result, "totally-not-a-subcommand")
    assert_no_connection_attempted(result)


@pytest.mark.parametrize("action", [
    "search",
    "modify",
    "create-user",
    "create-computer",
    "spn",
    "shadow-credentials",
    "group",
    "rbcd",
    "laps",
    "detect-signing",
    "detect-channel-binding",
    "shell",
    "delete-object",
])
def test_action_without_host_rejects(action: str) -> None:
    """Every action requires --host. Hitting the network is a regression."""
    result = run([action])
    assert result.exit_code == 2
    assert_contains(result, "--host is required")
    assert_no_connection_attempted(result)
