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
