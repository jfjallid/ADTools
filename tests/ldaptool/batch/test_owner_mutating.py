"""owner: read / backup / set / restore round-trip.

Changes the Owner SID of an object's nTSecurityDescriptor (cf. impacket's
owneredit.py). Uses two disposable users — a victim (the object whose owner
we rewrite) and an attacker (the principal we hand ownership to). The write
is scoped to the OWNER portion via the SD-flags control, so only the owner
changes.
"""

from __future__ import annotations

import os
import re
from typing import Callable

import pytest

from lib.ad import build_user_dn
from lib.assertions import assert_call_succeeded, assert_contains
from lib.runner import run, run_quiet
from lib.target import Target

pytestmark = pytest.mark.destructive


def _mk_user(
    target: Target,
    base_dn: str,
    name: str,
    request: pytest.FixtureRequest,
) -> str:
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: run_quiet([
        "delete-object", *target.common_argv(), "--dn", dn,
    ]))
    result = run([
        "create-user",
        *target.common_argv(),
        "--cn", name,
        "--sam", name,
    ])
    assert_call_succeeded(result)
    return dn


def _sid_of(target: Target, sam: str) -> str:
    """Resolve a sAMAccountName to its objectSid string (S-1-5-...)."""
    result = run([
        "search",
        *target.common_argv(),
        "--filter", f"(sAMAccountName={sam})",
        "--attrs", "objectSid",
        "--no-banner",
    ])
    assert_call_succeeded(result)
    m = re.search(r"objectSid:\s*(S-1-\S+)", result.combined)
    assert m, f"could not find objectSid for {sam!r}: {result!r}"
    return m.group(1)


def _read_owner(target: Target, victim: str) -> str:
    """Run `owner --action read` and return the printed owner SID."""
    result = run([
        "owner", *target.common_argv(),
        "--action", "read",
        "--target", victim,
    ])
    assert_call_succeeded(result)
    m = re.search(r"Owner:\s*(S-1-\S+)", result.combined)
    assert m, f"no owner SID in read output: {result!r}"
    return m.group(1)


@pytest.fixture
def owner_pair(
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> tuple[str, str]:
    """Returns (victim_sam, attacker_sam) — both freshly created users."""
    victim = ldaptest_name("ownv")
    attacker = ldaptest_name("owna")
    _mk_user(target, base_dn, victim, request)
    _mk_user(target, base_dn, attacker, request)
    return victim, attacker


def test_owner_read_backup_set_restore(
    target: Target,
    owner_pair: tuple[str, str],
    tmp_path,
) -> None:
    victim, attacker = owner_pair
    backup_file = str(tmp_path / f"{victim}.owner")

    original_owner = _read_owner(target, victim)
    attacker_sid = _sid_of(target, attacker)
    # Sanity: the object isn't already owned by the attacker.
    assert original_owner != attacker_sid, "test precondition: distinct owners"

    # Backup the current owner to a file.
    backup = run([
        "owner", *target.common_argv(),
        "--action", "backup",
        "--target", victim,
        "--file", backup_file,
    ])
    assert_call_succeeded(backup)
    assert os.path.exists(backup_file), f"backup not written at {backup_file}"

    # Set the owner to the attacker by sAMAccountName.
    set_by_name = run([
        "owner", *target.common_argv(),
        "--action", "set",
        "--target", victim,
        "--owner", attacker,
    ])
    assert_call_succeeded(set_by_name)
    assert_contains(set_by_name, attacker_sid)
    assert _read_owner(target, victim) == attacker_sid, "owner not changed to attacker"

    # Restore the original owner from the backup file.
    restore = run([
        "owner", *target.common_argv(),
        "--action", "restore",
        "--target", victim,
        "--file", backup_file,
    ])
    assert_call_succeeded(restore)
    assert _read_owner(target, victim) == original_owner, "owner not restored"


def test_owner_set_by_sid(
    target: Target,
    owner_pair: tuple[str, str],
) -> None:
    """The --owner flag also accepts a raw SID (not just a name)."""
    victim, attacker = owner_pair
    attacker_sid = _sid_of(target, attacker)

    set_by_sid = run([
        "owner", *target.common_argv(),
        "--action", "set",
        "--target", victim,
        "--owner", attacker_sid,
    ])
    assert_call_succeeded(set_by_sid)
    assert _read_owner(target, victim) == attacker_sid, "owner not changed via SID form"
