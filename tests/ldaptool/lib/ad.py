"""Active Directory helpers built on top of the ldaptool binary.

Cleanup primitives for mutating tests (delete-DN, look up DN by sAMAccountName).
Lookup helpers used in assertions (find an attribute value on an object).
All call out to the binary under test — no separate LDAP client.
"""

from __future__ import annotations

import re
from typing import Optional

from .runner import Result, run, run_quiet
from .target import Target


def find_dn_by_sam(target: Target, sam: str) -> Optional[str]:
    """Resolve a sAMAccountName to its DN. Returns None if not found."""
    result = run([
        "search",
        *target.common_argv(),
        "--filter", f"(sAMAccountName={sam})",
        "--attrs", "distinguishedName",
        "--no-banner",
    ])
    m = re.search(r"^dn:\s*(.+)$", result.combined, re.MULTILINE)
    if m:
        return m.group(1).strip()
    # Human-format prints "DN: <dn>" instead of "dn: <dn>".
    m = re.search(r"DN:\s*(.+)$", result.combined, re.MULTILINE)
    if m:
        return m.group(1).strip()
    return None


def search_attr(target: Target, sam: str, attr: str) -> Result:
    """Search for an object by sAMAccountName, returning a single attribute."""
    return run([
        "search",
        *target.common_argv(),
        "--filter", f"(sAMAccountName={sam})",
        "--attrs", attr,
        "--no-banner",
    ])


def search_dn(
    target: Target,
    dn: str,
    attrs: str = "*",
    extra_args: Optional[list[str]] = None,
) -> Result:
    """Base-scope search for a single DN — handy for asserting state."""
    args = [
        "search",
        *target.common_argv(),
        "--search-base", dn,
        "--scope", "base",
        "--filter", "(objectClass=*)",
        "--attrs", attrs,
        "--no-banner",
    ]
    if extra_args:
        args.extend(extra_args)
    return run(args)


def delete_dn(target: Target, dn: str) -> Result:
    """Cleanup helper: delete a DN via the new delete-object subcommand.

    Uses run_quiet so a failure (e.g. object already gone) doesn't mask
    the test's primary assertion failure.
    """
    return run_quiet([
        "delete-object",
        *target.common_argv(),
        "--dn", dn,
    ])


def delete_by_sam(target: Target, sam: str) -> None:
    """Lookup-then-delete: best-effort cleanup by sAMAccountName."""
    dn = find_dn_by_sam(target, sam)
    if dn:
        delete_dn(target, dn)


def build_user_dn(cn: str, base_dn: str) -> str:
    """Compose the DN that `create-user` will produce for a given CN.

    The tool defaults the OU to CN=Users,<base-dn> and uses `cn` verbatim
    as the RDN value (unescaped — sufficient for our ldaptest_* names
    which contain no DN special chars).
    """
    return f"CN={cn},CN=Users,{base_dn}"


def build_computer_dn(cn: str, base_dn: str) -> str:
    """DN that `create-computer` produces. CN is upper-cased by the tool."""
    return f"CN={cn.upper()},CN=Computers,{base_dn}"
