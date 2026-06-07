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

    # With no --pfx-pass / --no-pfx-pass, the tool generates a random password
    # and prints it (flagged "(generated)"). Capture it to open the PFX.
    m_pass = re.search(r"PFX pass:\s*(\S+)\s*\(generated\)", add.combined)
    assert m_pass, f"expected a generated PFX pass in output:\n{add.combined}"
    generated_pass = m_pass.group(1)

    # If openssl is on PATH, sanity-check the PFX is parseable with the
    # generated password. The tool writes legacy SHA1+RC2-40 encryption, so
    # OpenSSL 3.x needs -legacy.
    if shutil.which("openssl"):
        proc = subprocess.run(
            ["openssl", "pkcs12", "-info", "-in", pfx_path,
             "-passin", f"pass:{generated_pass}", "-noout", "-legacy"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert proc.returncode == 0, "PFX is not a valid PKCS#12"

        # The empty password must NOT open the default (now-encrypted) PFX.
        empty = subprocess.run(
            ["openssl", "pkcs12", "-info", "-in", pfx_path,
             "-passin", "pass:", "-noout", "-legacy"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert empty.returncode != 0, (
            "default PFX opened with an empty password — password not generated"
        )

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


def test_shadow_credentials_no_pfx_pass(
    target: Target,
    ldaps_available: None,
    victim_user: str,
    tmp_path,
) -> None:
    """`--no-pfx-pass` opts into the legacy empty-password behavior."""
    pfx_path = str(tmp_path / f"{victim_user}_empty.pfx")

    add = run([
        "shadow-credentials",
        *target.common_argv(),
        "--tls", "--insecure",
        "--action", "add",
        "--target", victim_user,
        "--out", pfx_path,
        "--no-pfx-pass",
    ])
    assert_call_succeeded(add)
    assert os.path.exists(pfx_path), f"PFX not written at {pfx_path}"
    assert re.search(r"PFX pass:\s*\(empty\)", add.combined), (
        f"expected an empty PFX pass in output:\n{add.combined}"
    )

    # Cleanup: clear the credential we just added (no device-id needed).
    clear = run([
        "shadow-credentials",
        *target.common_argv(),
        "--tls", "--insecure",
        "--action", "clear",
        "--target", victim_user,
    ])
    assert_call_succeeded(clear)

    # If openssl is on PATH, the empty password must open the PFX.
    if shutil.which("openssl"):
        proc = subprocess.run(
            ["openssl", "pkcs12", "-info", "-in", pfx_path,
             "-passin", "pass:", "-noout", "-legacy"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert proc.returncode == 0, (
            "--no-pfx-pass PFX did not open with an empty password"
        )


def test_shadow_credentials_with_pfx_pass(
    target: Target,
    ldaps_available: None,
    victim_user: str,
    tmp_path,
) -> None:
    """`--pfx-pass <pw>` encrypts the PFX with a non-empty password.

    The stock case uses an empty PFX password; this verifies the password
    plumbing by writing with one password, then proving the PFX cannot be
    opened without it.
    """
    pfx_path = str(tmp_path / f"{victim_user}_pwd.pfx")
    pfx_password = "shadow123"

    add = run([
        "shadow-credentials",
        *target.common_argv(),
        "--tls", "--insecure",
        "--action", "add",
        "--target", victim_user,
        "--out", pfx_path,
        "--pfx-pass", pfx_password,
    ])
    assert_call_succeeded(add)
    assert os.path.exists(pfx_path), f"PFX not written at {pfx_path}"

    # Cleanup: clear the credential we just added (no device-id needed).
    clear = run([
        "shadow-credentials",
        *target.common_argv(),
        "--tls", "--insecure",
        "--action", "clear",
        "--target", victim_user,
    ])
    assert_call_succeeded(clear)

    # If openssl is on PATH, prove the PFX is encrypted with this password.
    # The tool writes legacy SHA1+RC2-40 encryption, so OpenSSL 3.x needs -legacy.
    if not shutil.which("openssl"):
        pytest.skip("openssl not on PATH — cannot verify PFX encryption")

    with_correct = subprocess.run(
        ["openssl", "pkcs12", "-info", "-in", pfx_path,
         "-passin", f"pass:{pfx_password}", "-noout", "-legacy"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert with_correct.returncode == 0, (
        "PFX should open with the correct --pfx-pass"
    )

    with_wrong = subprocess.run(
        ["openssl", "pkcs12", "-info", "-in", pfx_path,
         "-passin", "pass:WRONG_PASSWORD", "-noout", "-legacy"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert with_wrong.returncode != 0, (
        "PFX opened with the wrong password — --pfx-pass not enforced"
    )
