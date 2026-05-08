"""Pytest configuration shared across all tiers.

Tier 1 (validation) needs no fixtures beyond a probe that the compiled
binary exists. Tier 2 adds the `target` fixture (loaded from LDAPTOOL_*
env vars), an `ldaptest_name` fixture for unique mutation namespaces,
a `base_dn` fixture that resolves the directory's base DN once per
session, and an `ldaps_available` gate for tests that need TLS.
"""

from __future__ import annotations

import itertools
import os
import re
import sys
from typing import Callable

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from lib.runner import binary_path, run  # noqa: E402
from lib.target import Target, load_target, missing_required_message  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "validation: tier-1 cases that exit before any network attempt",
    )
    config.addinivalue_line(
        "markers",
        "destructive: mutating cases that change directory state",
    )


@pytest.fixture(scope="session", autouse=True)
def _binary_present() -> None:
    """Hard-fail early if the binary isn't built — message is friendlier."""
    path = binary_path()
    if not os.path.exists(path):
        pytest.exit(
            f"binary not found at {path!r}. Build with `make` from the repo root, "
            "or set LDAPTOOL_BIN to a built binary path.",
            returncode=2,
        )
    if not os.access(path, os.X_OK):
        pytest.exit(f"binary at {path!r} is not executable", returncode=2)


@pytest.fixture(scope="session")
def target() -> Target:
    """Live-target connection details, loaded from LDAPTOOL_* env vars.

    Skips the test cleanly if the required vars aren't set.
    """
    t = load_target()
    if t is None:
        pytest.skip(missing_required_message())
    return t


@pytest.fixture(scope="session")
def worker_id(request: pytest.FixtureRequest) -> str:
    """xdist-aware worker id; falls back to 'master' when running serial."""
    return getattr(request.config, "workerinput", {}).get("workerid", "master")


_LDAPTEST_COUNTERS: dict[str, "itertools.count[int]"] = {}


@pytest.fixture
def ldaptest_name(worker_id: str) -> Callable[[str], str]:
    """Reserve a unique `ldaptest_<svc>[_<worker>]_<n>` name per call.

    Mutating tests use this to namespace created objects so parallel runs
    don't collide and orphans (after a panic) are obvious. AD caps
    sAMAccountName at 20 chars (19 for $-suffixed machine accounts), so
    the prefix is short and the worker tag is omitted when running serial.
    """
    def make(svc: str) -> str:
        counter = _LDAPTEST_COUNTERS.setdefault(svc, itertools.count(1))
        n = next(counter)
        if worker_id == "master":
            return f"lt_{svc}_{n}"
        return f"lt_{svc}_{worker_id}_{n}"
    return make


@pytest.fixture(scope="session")
def base_dn(target: Target) -> str:
    """Resolve the directory's default base DN once per session.

    Most tests don't need it explicitly (the tool auto-detects via RootDSE),
    but mutating tests building DNs for cleanup need it up front. Read from
    LDAPTOOL_BASE_DN if set; otherwise issue a base-scope probe and parse
    the resulting top-level DN.
    """
    if target.base_dn:
        return target.base_dn

    result = run([
        "search",
        *target.common_argv(),
        "--scope", "base",
        "--filter", "(objectClass=*)",
        "--attrs", "objectClass",
        "--no-banner",
    ])
    m = re.search(r"^DN:\s*(.+)$", result.combined, re.MULTILINE)
    if m:
        return m.group(1).strip()

    # Fall back to deriving from the host's FQDN suffix.
    host = target.host
    if "." in host:
        suffix = host.split(".", 1)[1]
        return ",".join(f"DC={p}" for p in suffix.split("."))
    return ",".join(f"DC={p}" for p in target.domain.split("."))


@pytest.fixture(scope="session")
def ldaps_available(target: Target) -> None:
    """Skip the test if LDAPS isn't reachable on the lab DC.

    `create-user --user-password`, `create-computer`, and
    `shadow-credentials --action add` all set unicodePwd, which
    requires a confidential connection. We probe with a cheap
    base-scope search over LDAPS.
    """
    result = run([
        "search",
        *target.common_argv(),
        "--tls",
        "--insecure",
        "--scope", "base",
        "--filter", "(objectClass=*)",
        "--attrs", "defaultNamingContext",
        "--no-banner",
    ])
    if "Failed to bind" in result.combined or "TLS handshake failed" in result.combined:
        pytest.skip("LDAPS not reachable on lab DC")
    if "connect failed" in result.combined:
        pytest.skip("LDAPS port unreachable")


@pytest.fixture
def shell(target: Target):
    """Spawn a fresh `ldaptool shell` session, yield it, then close it.

    Per-test (function-scoped) so a test that breaks the shell state
    doesn't pollute later tests. Each spawn re-establishes auth.
    """
    from lib.shell import LdapShell

    rs = LdapShell(target)
    try:
        yield rs
    finally:
        rs.close()
