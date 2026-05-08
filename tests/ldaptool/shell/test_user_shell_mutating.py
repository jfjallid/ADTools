"""createuser / createcomputer / deleteobject in the REPL."""

from __future__ import annotations

from typing import Callable

import pytest

from lib.ad import build_user_dn
from lib.runner import run_quiet
from lib.shell import LdapShell
from lib.target import Target

pytestmark = pytest.mark.destructive


def _cleanup(target: Target, dn: str) -> None:
    run_quiet(["delete-object", *target.common_argv(), "--dn", dn])


def test_createuser_in_shell(
    shell: LdapShell,
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    name = ldaptest_name("scu")
    dn = build_user_dn(name, base_dn)
    request.addfinalizer(lambda: _cleanup(target, dn))

    out = shell.cmd(f"createuser -cn {name} -sam {name}")
    assert "User created" in out, out
    assert dn.lower() in out.lower(), out


def test_deleteobject_in_shell(
    shell: LdapShell,
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> None:
    name = ldaptest_name("sdel")
    dn = build_user_dn(name, base_dn)
    # Insurance: even if the in-shell delete fails partway, this reaps.
    request.addfinalizer(lambda: _cleanup(target, dn))

    create = shell.cmd(f"createuser -cn {name} -sam {name}")
    assert "User created" in create, create

    delete = shell.cmd(f"deleteobject -dn {dn}")
    assert "Deleted" in delete, delete
