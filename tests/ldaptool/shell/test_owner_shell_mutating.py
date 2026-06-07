"""owner read / set in the interactive REPL.

Exercises the owner_shell.go dispatch path. The victim user is created
out-of-band (batch mode) so the test focuses on the in-shell owner
commands; owner edits are plain LDAP modifies, so the session-default
(plain-LDAP) shell fixture suffices.
"""

from __future__ import annotations

from typing import Callable

import pytest

from lib.ad import build_user_dn
from lib.assertions import assert_call_succeeded
from lib.runner import run, run_quiet
from lib.shell import LdapShell
from lib.target import Target

pytestmark = pytest.mark.destructive


def test_owner_read_set_in_shell(
    shell: LdapShell,
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    name = ldaptest_name("sown")
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: run_quiet([
        "delete-object", *target.common_argv(), "--dn", dn,
    ]))
    create = run(["create-user", *target.common_argv(), "--cn", name, "--sam", name])
    assert_call_succeeded(create)

    read = shell.cmd(f"owner -action read -target {name}")
    assert "Owner:" in read, read
    assert "Error" not in read, read

    set_out = shell.cmd(f"owner -action set -target {name} -owner Administrator")
    assert "changed" in set_out, set_out
    assert "Error" not in set_out, set_out
