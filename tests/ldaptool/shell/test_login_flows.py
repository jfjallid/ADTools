"""Login / global / error-path tests for the interactive shell.

The shell connects + binds during spawn (cmdloop is reached only on
success), so most "negative" cases are issued *after* a successful
spawn — invalid commands, logout-then-call, unknown handlers — and
assert that the prompt comes back without the shell exiting.
"""

from __future__ import annotations

from lib.shell import LdapShell


def test_help_lists_known_commands(shell: LdapShell) -> None:
    out = shell.cmd("help")
    assert "General commands" in out, out
    assert "search" in out.lower(), out
    assert "modify" in out.lower(), out
    assert "deleteobject" in out.lower(), out


def test_unknown_command_does_not_exit(shell: LdapShell) -> None:
    out = shell.cmd("frobozz_command_42")
    assert "Unknown command" in out, out
    # Shell still alive — issue another command to prove prompt returns.
    out2 = shell.cmd("toggleverbose")
    assert "verbose" in out2.lower(), out2


def test_toggle_verbose(shell: LdapShell) -> None:
    out_on = shell.cmd("toggleverbose")
    out_off = shell.cmd("toggleverbose")
    # Two toggles bring us back; both should mention the verbose state.
    assert "verbose" in out_on.lower(), out_on
    assert "verbose" in out_off.lower(), out_off


def test_setbasedn(shell: LdapShell, base_dn: str) -> None:
    """`setbasedn` updates the working base DN for subsequent searches."""
    out = shell.cmd(f"setbasedn {base_dn}")
    # Acceptance is implicit (no error); the shell prints the new base.
    assert "Error" not in out, out
    # Use a base-scope search to confirm the new base is honoured.
    out2 = shell.cmd("search -filter (objectClass=*) -scope base -attrs dn -no-banner")
    assert "Found" in out2, out2


def test_logout_then_service_command_says_not_connected(shell: LdapShell) -> None:
    out = shell.cmd("logout")
    assert "Disconnected" in out, out

    out2 = shell.cmd("search -filter (objectClass=*) -scope base -no-banner")
    assert "Not connected" in out2, out2


def test_describe_known_dn(shell: LdapShell, base_dn: str) -> None:
    """`describe <dn>` does a base-scope dump of a single object."""
    out = shell.cmd(f"describe {base_dn}")
    assert "DN:" in out, out
    assert base_dn.lower() in out.lower(), out
