"""Subprocess wrapper for the ldaptool binary.

ldaptool exits 0 on success and non-zero on failure (1 for runtime errors,
2 for flag/usage errors). Most tests assert on output substrings rather
than exit codes, but exit_code is exposed for cases where it's diagnostic.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Sequence


_HERE = os.path.dirname(os.path.abspath(__file__))
_TESTS_DIR = os.path.dirname(_HERE)
_REPO_ROOT = os.path.dirname(os.path.dirname(_TESTS_DIR))
DEFAULT_BIN = os.path.join(_REPO_ROOT, "bin", "ldaptool")
DEFAULT_TIMEOUT = 30  # ldap binds + searches can be slower than rpcclient


@dataclass
class Result:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str

    @property
    def combined(self) -> str:
        return self.stdout + "\n" + self.stderr

    def __repr__(self) -> str:  # pragma: no cover - test diagnostics only
        head_out = "\n".join(self.stdout.splitlines()[:8])
        head_err = "\n".join(self.stderr.splitlines()[:8])
        return (
            f"Result(argv={self.argv!r}, exit={self.exit_code},\n"
            f"  stdout (head):\n{head_out}\n"
            f"  stderr (head):\n{head_err}\n)"
        )


def binary_path() -> str:
    return os.environ.get("LDAPTOOL_BIN", DEFAULT_BIN)


def run(args: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> Result:
    """Spawn the binary with the given args, capture both streams.

    The binary prompts for a password on stdin if --pass / --hash / --aes-key
    / --no-pass / --anonymous are all absent and AD_PASSWORD is unset; we
    feed /dev/null so any unintended prompt fails fast rather than hanging.
    """
    argv = [binary_path(), *args]
    proc = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        text=True,
    )
    return Result(
        argv=argv,
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def run_quiet(args: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> Result:
    """Same as run() but used for cleanup steps where failures are tolerable.

    Subprocess timeouts still surface; the caller is expected to swallow
    assertion failures, not subprocess errors.
    """
    return run(args, timeout=timeout)
