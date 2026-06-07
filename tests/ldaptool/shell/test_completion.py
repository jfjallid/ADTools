"""TAB completion in the REPL: command names and -attrs values.

The shell uses golang's term package, which calls term.MakeRaw on stdin
and routes a tab byte through the AutoCompleteCallback registered in
shell.go. Driving this needs a real PTY (pexpect provides one) and a
direct send() of the tab character — `sendline` adds a newline.
"""

from __future__ import annotations

from lib.shell import LdapShell


def test_command_name_tab_completion(shell: LdapShell) -> None:
    """Unique prefix `rec` → completes to `reconnect`, which then runs.

    Send `rec`, a tab (\\t), then Enter (\\r). The term library expands
    the line to `reconnect` before the Enter is processed; we observe
    the side-effect, namely the `Reconnected to ...` diagnostic that
    only `reconnect` prints.
    """
    shell.proc.send("rec\t\r")
    out = shell.wait_for_prompt(timeout=20)
    assert "Reconnected to" in out, out


def test_command_name_tab_completion_ambiguous(shell: LdapShell) -> None:
    """Ambiguous prefix `lo` → lists candidates without rewriting the line.

    The autocompletion callback prints each candidate on its own line as
    `<usage> - <description>`. We assert that two candidates we expect
    (logout and login) both surface, then send Enter on the partial
    line to clear the prompt cleanly.
    """
    shell.proc.send("lo\t")
    # Both logout and login should be listed by the candidate dump.
    shell.proc.expect("logout", timeout=10)
    shell.proc.expect("login", timeout=10)
    # Clear the partial line — sending \r executes "lo" which is unknown
    # but harmless; the next prompt brings us back.
    shell.proc.send("\r")
    out = shell.wait_for_prompt(timeout=10)
    # The shell should emit "Unknown command" for "lo" and re-prompt.
    assert "Unknown command" in out, out


def test_attrs_tab_completion(shell: LdapShell) -> None:
    """After `-attrs `, tab completes against the common-AD-attrs list.

    `displ` is a unique prefix in commonADAttrs → completes to
    `displayName`. We type a full search command around it so that
    after the tab, the completed line forms a valid query, then press
    Enter. We expect the search to succeed and the response to include
    a `displayName:` line for Administrator.
    """
    # Type up to (and including) the prefix to be completed.
    shell.proc.send(
        "search -filter (sAMAccountName=Administrator) -attrs displ"
    )
    shell.proc.send("\t")
    # After the tab, the line buffer should contain `displayName`. Append
    # the rest of the command so the final form is a valid search.
    shell.proc.send(" -no-banner\r")
    out = shell.wait_for_prompt(timeout=20)
    assert "Found 1 entry" in out, out
    assert "displayName" in out, out
