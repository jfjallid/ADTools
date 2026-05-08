"""pexpect-based driver for the ldaptool interactive shell.

The shell uses golang's term package which calls term.MakeRaw on stdin,
so a real PTY is required — pipes won't work. pexpect provides one.
The shell emits ANSI sequences in raw-terminal mode, so output is
ANSI-stripped before assertions.

Spawn flow:
1. Build argv from a Target (`shell` action + connection flags).
2. Wait for the welcome banner ("Welcome to the interactive shell")
   followed by the "# " prompt.
3. Each `cmd()` sends a line, expects the prompt back, returns the
   accumulated output (with ANSI stripped) for assertions.
4. `close()` sends `exit` and reaps the process.
"""

from __future__ import annotations

import re
from typing import Optional, Sequence

import pexpect

from .runner import binary_path
from .target import Target


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\r")

# The shell uses the literal `(ldap) # ` prompt (see shell.go).
_PROMPT_PATTERN = r"\(ldap\) # "
_FIRST_PROMPT_PATTERN = r"\(ldap\) # (?=\Z)"
_WELCOME_BANNER = "Welcome to ldaptool!"


def _clean(text: str) -> str:
    return _ANSI_RE.sub("", text)


DEFAULT_SPAWN_TIMEOUT = 30
DEFAULT_CMD_TIMEOUT = 20


class LdapShell:
    """A live pexpect-driven `ldaptool shell` session."""

    def __init__(
        self,
        target: Target,
        extra_args: Optional[Sequence[str]] = None,
        timeout: float = DEFAULT_SPAWN_TIMEOUT,
    ) -> None:
        argv = ["shell", *target.common_argv()]
        if extra_args:
            argv.extend(extra_args)
        self._argv = argv
        self._proc = pexpect.spawn(
            binary_path(),
            list(argv),
            encoding="utf-8",
            timeout=timeout,
            dimensions=(40, 200),
        )
        self._proc.expect(_WELCOME_BANNER, timeout=timeout)
        self._proc.expect(_FIRST_PROMPT_PATTERN, timeout=timeout)
        self._last_output = _clean(self._proc.before or "")

    def _wait_for_prompt(self, timeout: float) -> str:
        self._proc.expect(_PROMPT_PATTERN, timeout=timeout)
        return _clean(self._proc.before or "")

    def wait_for_prompt(self, timeout: float = DEFAULT_CMD_TIMEOUT) -> str:
        return self._wait_for_prompt(timeout)

    def cmd(self, line: str, timeout: float = DEFAULT_CMD_TIMEOUT) -> str:
        self._proc.sendline(line)
        out = self._wait_for_prompt(timeout)
        if out.startswith(line):
            out = out[len(line):].lstrip("\r\n")
        self._last_output = out
        return out

    def expect_substr(
        self,
        line: str,
        needle: str,
        timeout: float = DEFAULT_CMD_TIMEOUT,
    ) -> str:
        out = self.cmd(line, timeout=timeout)
        if needle not in out:
            raise AssertionError(
                f"expected {needle!r} in output of {line!r}\n"
                f"argv: {self._argv!r}\n"
                f"output:\n{out}"
            )
        return out

    def send_password(self, password: str, prompt_substr: str) -> None:
        self._proc.expect(prompt_substr, timeout=DEFAULT_CMD_TIMEOUT)
        self._proc.sendline(password)

    def send_input(self, value: str, prompt_substr: str) -> None:
        self._proc.expect(prompt_substr, timeout=DEFAULT_CMD_TIMEOUT)
        self._proc.sendline(value)

    def close(self) -> None:
        if self._proc.closed:
            return
        try:
            self._proc.sendline("exit")
            self._proc.expect(pexpect.EOF, timeout=10)
        except (pexpect.TIMEOUT, pexpect.EOF, OSError):
            pass
        self._proc.close(force=True)

    @property
    def last_output(self) -> str:
        return self._last_output

    @property
    def proc(self) -> pexpect.spawn:
        return self._proc
