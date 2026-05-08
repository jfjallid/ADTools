"""`--naming-context` selects which RootDSE NC the search base is taken from.

Each NC has a recognisable top-level object: the configuration NC has
`CN=Configuration,...`, the schema NC has `CN=Schema,CN=Configuration,...`,
and the root NC matches the default forest root.
"""

from __future__ import annotations

from lib.assertions import assert_call_succeeded, assert_contains
from lib.runner import run
from lib.target import Target


def _search(target: Target, *args: str) -> list[str]:
    return ["search", *target.common_argv(), *args]


def test_naming_context_configuration(target: Target) -> None:
    result = run(_search(
        target,
        "--naming-context", "configuration",
        "--scope", "base",
        "--filter", "(objectClass=*)",
        "--attrs", "objectClass",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    assert_contains(result, "CN=Configuration")


def test_naming_context_schema(target: Target) -> None:
    result = run(_search(
        target,
        "--naming-context", "schema",
        "--scope", "base",
        "--filter", "(objectClass=*)",
        "--attrs", "objectClass",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    assert_contains(result, "CN=Schema")


def test_naming_context_root(target: Target) -> None:
    result = run(_search(
        target,
        "--naming-context", "root",
        "--scope", "base",
        "--filter", "(objectClass=*)",
        "--attrs", "objectClass",
        "--no-banner",
    ))
    assert_call_succeeded(result)
    assert_contains(result, "DC=")
