"""shadow-credentials: add / list / remove / clear cycle.

The `add` action writes a Key Credential blob to msDS-KeyCredentialLink
(requires LDAPS for unicodePwd-grade auth) and exports a PKCS#12 PFX
file with the generated cert + private key.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Callable

import pytest

from lib.ad import build_user_dn
from lib.assertions import assert_call_succeeded
from lib.runner import run, run_quiet
from lib.target import Target

pytestmark = pytest.mark.destructive


@pytest.fixture
def victim_user(
    target: Target,
    base_dn: str,
    ldaptest_name: Callable[[str], str],
    request: pytest.FixtureRequest,
) -> str:
    name = ldaptest_name("shadow")
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
    return name


def test_shadow_credentials_add_list_remove_clear(
    target: Target,
    ldaps_available: None,
    victim_user: str,
    tmp_path,
) -> None:
    pfx_path = str(tmp_path / f"{victim_user}.pfx")

    add = run([
        "shadow-credentials",
        *target.common_argv(),
        "--tls", "--insecure",
        "--action", "add",
        "--target", victim_user,
        "--out", pfx_path,
    ])
    assert_call_succeeded(add)
    # Output mentions the device-id; capture it for the targeted remove.
    assert os.path.exists(pfx_path), f"PFX not written at {pfx_path}"

    # If openssl is on PATH, sanity-check the PFX is parseable. The tool
    # writes legacy SHA1+RC2-40 encryption, so OpenSSL 3.x needs -legacy.
    if shutil.which("openssl"):
        proc = subprocess.run(
            ["openssl", "pkcs12", "-info", "-in", pfx_path,
             "-passin", "pass:", "-noout", "-legacy"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert proc.returncode == 0, "PFX is not a valid PKCS#12"

    listed = run([
        "shadow-credentials",
        *target.common_argv(),
        "--action", "list",
        "--target", victim_user,
    ])
    assert_call_succeeded(listed)

    # Parse a device-id from the list output to drive the targeted remove.
    m = re.search(r"Device ID:\s*([0-9a-fA-F-]+)", listed.combined)
    if m:
        device_id = m.group(1)
        rm = run([
            "shadow-credentials",
            *target.common_argv(),
            "--tls", "--insecure",
            "--action", "remove",
            "--target", victim_user,
            "--device-id", device_id,
        ])
        assert_call_succeeded(rm)

    # Re-add then clear empties the attribute.
    pfx2 = str(tmp_path / f"{victim_user}_2.pfx")
    run([
        "shadow-credentials",
        *target.common_argv(),
        "--tls", "--insecure",
        "--action", "add",
        "--target", victim_user,
        "--out", pfx2,
    ])
    clear = run([
        "shadow-credentials",
        *target.common_argv(),
        "--tls", "--insecure",
        "--action", "clear",
        "--target", victim_user,
    ])
    assert_call_succeeded(clear)
