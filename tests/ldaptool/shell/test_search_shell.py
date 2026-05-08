"""Search / modify in the REPL — read paths."""

from __future__ import annotations

from lib.shell import LdapShell


def test_search_in_shell(shell: LdapShell) -> None:
    out = shell.cmd(
        "search -filter (sAMAccountName=Administrator) -attrs cn -no-banner"
    )
    assert "Found 1 entry" in out, out
    assert "Administrator" in out, out


def test_search_with_ldif_in_shell(shell: LdapShell) -> None:
    out = shell.cmd(
        "search -filter (sAMAccountName=Administrator) -attrs cn -ldif -no-banner"
    )
    assert "version: 1" in out, out
    assert "dn: " in out, out


def test_search_with_json_in_shell(shell: LdapShell) -> None:
    out = shell.cmd(
        "search -filter (sAMAccountName=Administrator) -attrs cn -json -no-banner"
    )
    # Output starts with `[` for the array.
    assert out.lstrip().startswith("["), out
    assert "Administrator" in out, out
