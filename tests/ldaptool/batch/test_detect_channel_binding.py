"""`detect-channel-binding` probes the DC's channel-binding policy.

The action implicitly enables --tls if neither --tls nor --starttls is
supplied, so passing --insecure is sufficient on a lab DC with a
self-signed cert.
"""

from __future__ import annotations

from lib.assertions import assert_call_succeeded, assert_contains
from lib.runner import run
from lib.target import Target


def test_detect_channel_binding_returns_boolean(
    target: Target,
    ldaps_available: None,
) -> None:
    result = run([
        "detect-channel-binding",
        *target.common_argv(),
        "--tls",
        "--insecure",
    ])
    assert_call_succeeded(result)
    assert_contains(result, "LDAP channel binding required:")
    combined = result.combined
    assert ("required: true" in combined) or ("required: false" in combined)


def test_detect_channel_binding_over_starttls(target: Target) -> None:
    """The tool also classifies the channel-binding policy via StartTLS.

    Same probe as the LDAPS path above, but bind transport is plain LDAP
    upgraded to TLS. If the lab DC doesn't support StartTLS we skip
    rather than fail.
    """
    import pytest

    result = run([
        "detect-channel-binding",
        *target.common_argv(),
        "--starttls",
        "--insecure",
    ])
    if "StartTLS failed" in result.combined:
        pytest.skip("StartTLS not supported on lab DC")
    assert_call_succeeded(result)
    assert_contains(result, "LDAP channel binding required:")
    combined = result.combined
    assert ("required: true" in combined) or ("required: false" in combined)
