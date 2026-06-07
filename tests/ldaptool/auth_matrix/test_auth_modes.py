"""Tier-0 auth-mode smoke matrix.

A single read-only call (`search --preset dcs --attrs sAMAccountName`)
repeated across every supported authentication path. The base tier-2
tests all run as NTLM-password; a regression in any other auth mode
would slip through without these.

Each case skips when its prerequisite env var is missing — the suite
gracefully reports which modes are exercisable on the current target.
"""

from __future__ import annotations

import os

import pexpect
import pytest

from lib.assertions import assert_call_succeeded, assert_contains
from lib.runner import binary_path, run
from lib.target import Target


def _read_only(target: Target, *cred_argv: str) -> list[str]:
    """Build a search invocation with the given credential flags.

    Connection flags (host, dc-ip, etc.) come from target.conn_argv();
    each test supplies its own credential flags via *cred_argv.
    """
    return [
        "search",
        *target.conn_argv(),
        *cred_argv,
        "--preset", "dcs",
        "--attrs", "sAMAccountName",
        "--no-banner",
    ]


def _assert_dcs(result) -> None:
    assert_call_succeeded(result)
    # The lab DC always identifies itself in the "DCs" preset output.
    assert_contains(result, "DC01")


def test_ntlm_password(target: Target) -> None:
    """Baseline: NTLM with --pass."""
    result = run(_read_only(
        target,
        "--user", target.user,
        "--pass", target.password,
        "--domain", target.domain,
    ))
    _assert_dcs(result)


def test_ntlm_password_prompt(target: Target) -> None:
    """No `--pass`/`-n`/`AD_PASSWORD` → prompt on stderr, read from TTY.

    The runner's normal `subprocess.run` plumbs stdin to /dev/null so any
    accidental prompt fails fast; this test deliberately drives a real
    PTY via pexpect to feed the prompt.
    """
    argv = [
        "search",
        *target.conn_argv(),
        "--user", target.user,
        "--domain", target.domain,
        "--preset", "dcs",
        "--attrs", "sAMAccountName",
        "--no-banner",
    ]
    # Strip AD_PASSWORD so the binary actually prompts.
    env = {k: v for k, v in os.environ.items() if k != "AD_PASSWORD"}
    proc = pexpect.spawn(
        binary_path(),
        argv,
        encoding="utf-8",
        timeout=30,
        env=env,  # type: ignore[arg-type]
        dimensions=(40, 200),
    )
    try:
        proc.expect("Enter password:", timeout=15)
        proc.sendline(target.password)
        proc.expect(pexpect.EOF, timeout=30)
        output = proc.before or ""
    finally:
        proc.close(force=True)
    assert "DC01" in output, f"prompt-based auth didn't surface DCs:\n{output}"


def test_ntlm_hash(target: Target) -> None:
    if not target.nthash:
        pytest.skip("LDAPTOOL_NTHASH not set")
    result = run(_read_only(
        target,
        "--user", target.user,
        "--hash", target.nthash,
        "--domain", target.domain,
    ))
    _assert_dcs(result)


def test_simple_bind_over_tls(target: Target) -> None:
    """`--simple` requires TLS or --sasl=none. Use TLS."""
    user_dn = f"{target.user}@{_realm_from_host(target)}"
    result = run([
        "search",
        *target.conn_argv(),
        "--simple",
        "--tls",
        "--insecure",
        "--user", user_dn,
        "--pass", target.password,
        "--preset", "dcs",
        "--attrs", "sAMAccountName",
        "--no-banner",
    ])
    if "Failed to bind" in result.combined or "TLS handshake failed" in result.combined:
        pytest.skip("LDAPS or simple bind not available on lab DC")
    _assert_dcs(result)


def test_anonymous_bind(target: Target) -> None:
    """Anonymous binds are usually rejected on modern AD; verify clean rejection.

    The point isn't that anonymous works (it doesn't on hardened DCs),
    it's that the --anonymous code path doesn't crash and produces a
    recognisable result one way or the other.
    """
    result = run([
        "search",
        *target.conn_argv(),
        "--anonymous",
        "--scope", "base",
        "--filter", "(objectClass=*)",
        "--attrs", "objectClass",
        "--no-banner",
    ])
    # Either succeeded (rare) or cleanly rejected with a recognisable error.
    if "Found" in result.combined:
        return
    rejected_markers = (
        "operation not allowed",
        "STATUS_ACCESS_DENIED",
        "could not detect base DN",
        "[Error]",
        "Error:",
    )
    if not any(m in result.combined for m in rejected_markers):
        raise AssertionError(f"unexpected output for --anonymous: {result!r}")


def test_kerberos_password(target: Target) -> None:
    """Kerberos with --pass (requires FQDN host and reachable KDC).

    LDAPTOOL_DOMAIN is often the NetBIOS short form (e.g. "mydomain");
    Kerberos needs the FQDN-derived realm ("mydomain.local"). We pass
    --realm explicitly to avoid the AS-REQ realm mismatch.
    """
    if not target.dc_ip:
        pytest.skip("LDAPTOOL_DC_IP not set (Kerberos needs a KDC)")
    if "." not in target.host:
        pytest.skip("LDAPTOOL_HOST must be FQDN for Kerberos")
    realm = _realm_from_host(target).upper()
    result = run(_read_only(
        target,
        "--kerberos",
        "--user", target.user,
        "--pass", target.password,
        "--realm", realm,
    ))
    _assert_dcs(result)


def test_kerberos_aes_key(target: Target) -> None:
    if not target.aes_key:
        pytest.skip("LDAPTOOL_AES_KEY not set")
    if not target.dc_ip:
        pytest.skip("LDAPTOOL_DC_IP not set (Kerberos needs a KDC)")
    if "." not in target.host:
        pytest.skip("LDAPTOOL_HOST must be FQDN for Kerberos")
    realm = _realm_from_host(target).upper()
    result = run(_read_only(
        target,
        "--kerberos",
        "--user", target.user,
        "--aes-key", target.aes_key,
        "--realm", realm,
    ))
    _assert_dcs(result)


def test_tls_baseline(target: Target) -> None:
    """LDAPS baseline: NTLM-pass over TLS."""
    result = run([
        "search",
        *target.conn_argv(),
        "--tls",
        "--insecure",
        "--user", target.user,
        "--pass", target.password,
        "--domain", target.domain,
        "--preset", "dcs",
        "--attrs", "sAMAccountName",
        "--no-banner",
    ])
    if "TLS handshake failed" in result.combined:
        pytest.skip("LDAPS not reachable on lab DC")
    _assert_dcs(result)


def test_starttls_baseline(target: Target) -> None:
    """StartTLS baseline: NTLM-pass over plain LDAP upgraded with STARTTLS."""
    result = run([
        "search",
        *target.conn_argv(),
        "--starttls",
        "--insecure",
        "--user", target.user,
        "--pass", target.password,
        "--domain", target.domain,
        "--preset", "dcs",
        "--attrs", "sAMAccountName",
        "--no-banner",
    ])
    if "StartTLS failed" in result.combined:
        pytest.skip("StartTLS not supported on lab DC")
    _assert_dcs(result)


def _realm_from_host(target: Target) -> str:
    """Derive a UPN-style realm from the host's FQDN suffix."""
    if "." in target.host:
        return target.host.split(".", 1)[1]
    return target.domain
