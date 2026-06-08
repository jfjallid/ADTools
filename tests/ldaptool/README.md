# ldaptool integration test suite

Pytest-driven end-to-end tests for `ldaptool`.
Four tiers (validation, batch read-only, batch
mutating, interactive shell) plus an auth-mode smoke matrix.

## Layout

```
tests/ldaptool/
├── conftest.py             # session/per-test fixtures
├── pytest.ini              # markers
├── lib/                    # shared helpers
│   ├── runner.py           # subprocess wrapper + Result dataclass
│   ├── target.py           # LDAPTOOL_* env-var loader
│   ├── assertions.py       # assert_contains / assert_call_succeeded / ...
│   ├── shell.py            # pexpect driver for `ldaptool shell`
│   └── ad.py               # find_dn_by_sam, build_user_dn, delete_dn, …
├── scripts/cleanup.sh      # orphan sweep (lt_* objects)
├── validation/             # tier 1 (no network)
├── batch/                  # tier 2 (live DC, batch mode)
├── shell/                  # tier 3 (live DC, interactive REPL)
└── auth_matrix/            # tier 0 (one read-only call across auth paths)
```

## Prerequisites

```sh
# Build the binary:
make                       # produces bin/ldaptool

# Install Python deps (once):
pip install pytest pexpect
# Optional: pip install pytest-xdist  # for parallel runs
```

## Environment variables

Tier 1 needs no env vars. Tiers 0/2/3 read connection details from:

| Variable                 | Required | Description                                       |
|--------------------------|----------|---------------------------------------------------|
| `LDAPTOOL_HOST`          | yes      | DC FQDN (e.g. `dc01.domain.local`)             |
| `LDAPTOOL_USER`          | yes      | Privileged user (e.g. `administrator`)            |
| `LDAPTOOL_PASS`          | yes      | Password                                          |
| `LDAPTOOL_DOMAIN`        | yes      | NetBIOS or short domain name                      |
| `LDAPTOOL_DC_IP`         | no       | KDC IP (required for `--kerberos` cases)          |
| `LDAPTOOL_DNS_HOST`      | no       | DNS resolver override                             |
| `LDAPTOOL_NTHASH`        | no       | NT hash (enables NTLM-hash auth-matrix case)      |
| `LDAPTOOL_AES_KEY`       | no       | Hex AES key (enables Kerberos-AES case)           |
| `LDAPTOOL_BASE_DN`       | no       | Pin a base DN; otherwise probed from the DC       |
| `LDAPTOOL_BIN`           | no       | Path to a pre-built binary; defaults to `bin/ldaptool` |

Example for the mydomain lab:

```sh
export LDAPTOOL_HOST=dc01.mydomain.local
export LDAPTOOL_USER=administrator
export LDAPTOOL_PASS=P@ssword1
export LDAPTOOL_DOMAIN=mydomain
export LDAPTOOL_DC_IP=192.168.0.1
```

## Running

From the repo root:

```sh
# Tier 1 only — no network, fast, CI-safe
pytest tests/ldaptool/validation/

# Tier 2 read-only against the live DC
pytest tests/ldaptool/batch/ -m "not destructive"

# Tier 2 mutating (creates lt_* objects, deletes them in finalizers)
pytest tests/ldaptool/batch/ -m destructive

# Tier 3 interactive REPL
pytest tests/ldaptool/shell/

# Tier 0 auth-mode smoke matrix
pytest tests/ldaptool/auth_matrix/

# Everything
pytest tests/ldaptool/
```

## Mutation safety

Mutating tests reserve an `lt_<svc>[_<worker>]_<n>` namespace per object
(short to fit AD's 20-char `sAMAccountName` cap). Cleanup finalizers
register *before* the create, so a panic during creation still cleans
up the partial state. With `pytest-xdist`, each worker gets a distinct
namespace — runs are safe in parallel.

If a run is killed mid-test and leaves orphans, the safety-net script
sweeps them up:

```sh
bash tests/ldaptool/scripts/cleanup.sh
LDAPTOOL_DRY_RUN=1 bash tests/ldaptool/scripts/cleanup.sh   # preview
```

## What's tested

- **Tier 1 (36 cases)**: top-level help, `--version`, `--help` for every
  action, unknown-subcommand handling, `--host` requirement, `--ldif` /
  `--json` mutual exclusion, malformed `--scope` and `--preset`.
- **Tier 2 read-only**: every search flag (filter, all 9 presets, scope,
  attrs incl. operational-only, output formats, paging incl. `--page-size 0`,
  size limit, banner, out-file, controls — `show-deleted`, `server-sort`
  ascending/descending, multiple `--control`), `--naming-context`
  selection, `detect-signing`, `detect-channel-binding` (TLS + StartTLS),
  `laps` (with and without `--target`), `access` (full report, single
  `--right`, `--show-token`).
- **Tier 2 mutating**: `create-user` (no-pass, with password,
  optional attrs, `--ou` custom container, post-create bind),
  `create-computer` (default, `--password` + `--managed-by`,
  post-create bind), `modify` (--set/--add/--delete + `@file`),
  `spn` (add/remove/replace), `group` (user member, computer member
  with and without `$`), `rbcd` (sAMAccountName/SID, computer trustee),
  `shadow-credentials` (add/list/remove/clear with PFX validation,
  `--pfx-pass`), `dacl` (read, add/remove an ACE, backup/restore),
  `owner` (read/backup/set/restore round-trip, set by SID),
  `delete-object` (round-trip plus error paths).
- **Tier 3**: REPL help, `setbasedn`, `toggleverbose`, `logout`,
  unknown command, `describe`, `search` (human/LDIF/JSON), `createuser`,
  `createcomputer`, `deleteobject`, `modify`, `spn` (add/replace/remove),
  `group`, `rbcd`, `shadowcreds` (add/list/clear), `owner` (read/set),
  `laps` (bare and
  `-target`), connection lifecycle (`logout`+`connect`+`login`,
  `login_krb`, `reconnect`, `tls`), tab completion (commands + `-attrs`).
- **Tier 0**: NTLM-pass, NTLM password prompt, NTLM-hash, simple bind
  over TLS, anonymous bind, Kerberos with password, Kerberos with AES
  key, LDAPS baseline, StartTLS baseline.

Cases that depend on optional env vars (NTHASH, AES_KEY) skip cleanly
when those vars are unset.

## Adding tests

For a new mutating action:

1. Pick a short svc name (≤ 6 chars) — full pattern is `lt_<svc>_<n>`,
   capped at 20 chars to fit `sAMAccountName`.
2. Use the `ldaptest_name` fixture and `request.addfinalizer` *before*
   the create call. Finalizers run even on panic.
3. Use `lib.ad.delete_dn` (or `delete-object` directly) for cleanup —
   both are idempotent.
4. Mark the module `pytestmark = pytest.mark.destructive` so it's gated
   behind `-m destructive`.
