"""Connection-state machine in the REPL: connect, login, login_krb, tls, reconnect.

These commands are the only place the shell's underlying connArgs and
auth state are mutated post-spawn. Coverage here protects regressions
in shell.go's shellConnectFunc / shellLoginFunc / shellLoginKrbFunc and
the togglers in shell_extras.go.
"""

from __future__ import annotations

import pytest

from lib.shell import LdapShell
from lib.target import Target


def test_logout_then_connect_login_round_trip(shell: LdapShell, target: Target) -> None:
    """Full re-auth: logout → connect → login → search.

    After `logout`, service commands print "Not connected"; after
    `connect <host>` we have a TCP-only connection (still flagged as
    not authenticated); after `login <domain>/<user> <pass>` the
    authenticated flag flips back on and search works again.
    """
    out = shell.cmd("logout")
    assert "Disconnected" in out, out

    not_yet = shell.cmd("search -filter (objectClass=*) -scope base -no-banner")
    assert "Not connected" in not_yet, not_yet

    connected = shell.cmd(f"connect {target.host}")
    assert "Connected to" in connected, connected
    assert target.host in connected, connected

    # Connected but not yet authenticated — service commands still refuse.
    pre_login = shell.cmd("search -filter (objectClass=*) -scope base -no-banner")
    assert "Not connected" in pre_login, pre_login

    logged_in = shell.cmd(f"login {target.domain}/{target.user} {target.password}")
    assert "Logged in as" in logged_in, logged_in
    assert target.user in logged_in, logged_in

    after = shell.cmd(
        "search -filter (sAMAccountName=Administrator) -attrs cn -no-banner"
    )
    assert "Found 1 entry" in after, after


def test_login_krb_in_shell(shell: LdapShell, target: Target) -> None:
    """`login_krb <realm>/<user> <pass>` re-auths via Kerberos.

    Needs a reachable KDC (i.e. LDAPTOOL_DC_IP) and a host FQDN since
    the realm is derived from the host suffix.
    """
    if not target.dc_ip:
        pytest.skip("LDAPTOOL_DC_IP not set (Kerberos needs a KDC)")
    if "." not in target.host:
        pytest.skip("LDAPTOOL_HOST must be FQDN for Kerberos")

    realm = target.host.split(".", 1)[1].upper()

    shell.cmd("logout")
    shell.cmd(f"connect {target.host}")

    out = shell.cmd(f"login_krb {realm}/{target.user} {target.password}")
    assert "Kerberos login successful" in out, out

    after = shell.cmd(
        "search -filter (sAMAccountName=Administrator) -attrs cn -no-banner"
    )
    assert "Found 1 entry" in after, after


def test_reconnect_in_shell(shell: LdapShell) -> None:
    """`reconnect` reopens the TCP connection but resets auth state.

    After `reconnect` the connection is alive but unauthenticated; we
    call `login` to re-auth and confirm a search works again.
    """
    out = shell.cmd("reconnect")
    assert "Reconnected to" in out, out

    # Reconnect drops auth — verify a search refuses until re-login.
    pre = shell.cmd("search -filter (objectClass=*) -scope base -no-banner")
    assert "Not connected" in pre, pre


def test_tls_toggle_in_shell(shell: LdapShell) -> None:
    """`tls on|off|starttls` queues the transport setting for the *next* connection.

    The current connection is unaffected — this is just the connArgs
    bit flipping. Confirm the diagnostic strings the tool prints, since
    that's the test's only observable.
    """
    out_off = shell.cmd("tls off")
    assert "TLS disabled" in out_off, out_off

    out_starttls = shell.cmd("tls starttls")
    assert "StartTLS" in out_starttls, out_starttls

    out_on = shell.cmd("tls on")
    assert "TLS will be used" in out_on, out_on
