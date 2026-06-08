Coverage gaps below. Some of these are intentional (out of scope per the plan), others are real holes worth filling.

## Per-action gaps

**search** (the largest gap — biggest flag matrix)
- `--time-limit` (we only cover `--size-limit`)
- `--no-schema-hint`
- `--search-base` overriding the base
- The `Size Limit Exceeded` (LDAP code 4) error path — we explicitly avoid triggering it
- Output decoders (FILETIME, GUID, SID, logonHours) — never asserted
- LDIF base64 encoding for non-LDIF-safe values (binary attrs)
- JSON `{"base64": "..."}` binary representation
- `--out-file` with `--json` or human format (only LDIF tested)

**modify**
- `@file` indirection with **binary** content (we test text only — the real use case is `nTSecurityDescriptor`)
- Mixing `--set` / `--add` / `--delete` in one invocation
- Modifying a non-existent DN (error path)

**create-user**
- `--enabled` *without* `--user-password` (works in plain LDAP)
- Duplicate `sAMAccountName` (error path)

**create-computer**
- `--ou`, `--description` flags

**spn**
- Combined `--add` and `--remove` in one invocation

**shadow-credentials**
- Multiple shadow creds on one target (the intended attack workflow)
- `list` against a target with no shadow creds (empty result)
- `remove` with a non-existent device-id

**group**
- Multiple `--member` flags in one invocation
- DN-style group/member identifiers (we only test sAMAccountName)
- Member already in group (idempotency)

**rbcd**
- Multiple `--trustee` flags in one invocation
- DN-style trustee identifier (we test SID and sAMAccountName)
- Dedup behavior (add same trustee twice → assert single entry)
- Sort-order stability of `list` output

**dacl** (covered: read, add/remove a ResetPassword ACE, backup/restore)
- Object-ACE paths via `--right-guid` / `--inherited-object-guid` (only preset rights tested)
- `--ace-type denied` ACEs
- The domain-object DCSync findings banner (needs the domain head as target)
- `--mask` raw access-mask form

**owner** (covered: read, backup, set by name and by SID, restore)
- Setting owner by DN form (sAMAccountName and SID tested)
- `read` on an object with no owner present (degenerate case)

**access** (covered: full report, single `--right`, `--show-token`)
- `--no-session-sids`
- A principal that is NOT granted the queried right (negative/`not granted` path)
- `write:<attr>` / `read:<attr>` and bare-attribute right forms
- The `tokenGroups`-unavailable degraded fallback banner

**laps**
- A target with actual LAPS attrs (we assume the lab has none) — the tool's decode paths for `ms-Mcs-AdmPwd`, `msLAPS-Password`, and `msLAPS-EncryptedPassword` are exercised only structurally

**detect-signing / detect-channel-binding**
- `--kerberos` auth path
- Behavior on a server that *does* require signing or channel binding (we assert "returns a boolean," not the value)

**delete-object**
- Deleting a non-leaf DN (subtree behavior — should fail without subtree control)

## Connection / auth flag gaps

- `--port` (defaults only)
- `--sasl none|sign|seal` explicit values
- `--channel` (channel binding bind)
- `--timeout`
- `--socks-host` / `--socks-port`
- `--ccache` (Kerberos via cached ticket)
- `--krb5conf` (custom path)
- `--override-spn`
- `--dns-host` / `--dns-tcp`
- `--debug`, `--verbose` (log levels)

## Auth-matrix gaps (Tier 0)

- `--no-pass` / `-n` (unauthenticated NTLM bind)
- `--ccache` (cached Kerberos ticket)
- `--hash` + `--kerberos` (RC4 from NT hash)
- `--simple` over plain LDAP with `--sasl=none`
- `--channel` bind over TLS
- `--kerberos` over `--starttls`

## REPL gaps

The shell tier covers the common commands. Untested REPL paths:
- History persistence (`~/.ldaptool_history`)

## Error / negative paths

- Bind failures with bad credentials
- DC unreachable / TCP timeout
- Permission denied on a specific operation
- Schema violations (e.g. creating a user missing required attrs)
- LDAP referrals
- Network blips mid-operation

## Concurrency

- The `lt_<svc>_<worker>_<n>` namespace was *built* for `pytest-xdist`, but the suite is never actually run with `-n N` in CI. Parallel safety is theoretical until exercised.

## Out of scope (intentionally)

These are documented as out-of-scope in the plan, listed here for completeness:
- DPAPI-NG decryption of `msLAPS-EncryptedPassword`
- `go-smb` / `old-ldap/v3` library internals
- The existing in-package Go unit tests (`uac_test.go`, `rbcd_test.go`, `shell_test.go`) still run via `go test`
- Sibling tools (`atexec`, `dcsync`, `wmiexec`, etc.)

## Highest-value additions

If you want to expand the suite, in order of payoff:
1. **Output decoders** (FILETIME/GUID/SID/logonHours) — highly opaque code paths with no other test signal
2. **Multiple-flag forms** (`--add` + `--remove` in spn, multiple `--member`/`--trustee`) — common real-world usage
3. **`--ccache` Kerberos path** — the most-used Kerberos workflow on engagements