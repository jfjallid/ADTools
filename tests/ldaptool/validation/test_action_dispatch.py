"""Each action's `--help` prints a tailored usage block.

A typo in main.go's subcommand registration would make the dispatcher
miss the action; surfacing a per-action `--help` regression is cheap
insurance and catches that.
"""

from __future__ import annotations

import pytest

from lib.assertions import assert_contains, assert_no_connection_attempted
from lib.runner import run

pytestmark = pytest.mark.validation


# Each tuple: (action, substring that should appear in the help text).
# Substrings are picked from the per-action help blocks in spn.go,
# shadow.go, user.go, ldap.go, etc. — pick something specific enough
# that the help text can't accidentally match another action's block.
_ACTIONS = [
    ("search",                "Search options"),
    ("modify",                "Modify options"),
    ("create-user",           "Create user options"),
    ("create-computer",       "Create computer options"),
    ("spn",                   "Set SPN options"),
    ("shadow-credentials",    "Shadow credentials options"),
    ("group",                 "Group membership management"),
    ("rbcd",                  "Resource-Based Constrained Delegation"),
    ("dacl",                  "View and modify the DACL"),
    ("owner",                 "View and change the Owner SID"),
    ("access",                "Compute the effective access"),
    ("laps",                  "LAPS-managed"),
    ("detect-signing",        "Probes whether the target DC enforces LDAP signing"),
    ("detect-channel-binding", "channel binding"),
    ("shell",                 "interactive LDAP shell"),
    ("delete-object",         "Delete an LDAP object by DN"),
]


@pytest.mark.parametrize("action,marker", _ACTIONS)
def test_action_help(action: str, marker: str) -> None:
    """Every registered action surfaces a usage block via --help."""
    result = run([action, "--help"])
    # `--help` is consumed by Go's flag.ExitOnError → exit 0 with usage text.
    assert result.exit_code == 0
    assert_contains(result, marker)
    # The usage block always concatenates helpConnectionOptions.
    assert_contains(result, "Connection options:")
    assert_no_connection_attempted(result)
