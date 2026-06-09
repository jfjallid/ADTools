# gpoparser

Extract and analyse what Active Directory **Group Policy Objects** *do* (local-group
membership, privilege/user rights, registry changes, scripts, scheduled tasks,
services, and Group Policy Preferences) and *where* they apply (which OUs, domains
and computers, via `gPLink` inheritance).

It mirrors the functionality of [synacktiv/gpoParser](https://github.com/synacktiv/gpoParser)
but adds the extended authentication and connection options shared by the rest of
the adtools suite: full Kerberos / NTLM / pass-the-hash / AES, LDAPS, StartTLS,
channel binding, SASL signing/sealing, SOCKS5 and DNS override.

## Build

```sh
make -C tools/gpoparser     # builds ./tools/gpoparser/gpoparser
# or from the repo root:
make                        # builds all tools into bin/
```

## Workflow at a glance

`gpoparser` is built around a **JSON cache**. You first *collect* GPO data into a
cache (either live with `remote` or offline with `local`), then run the read-only
analysis subcommands (`display`, `query`, `assess`, `enrich`) against that cache —
no repeated DC round-trips.

```
            ┌─────────┐   collect    ┌──────────────────────────┐
  AD + SYSVOL│ remote  │─────────────▶│                          │
            └─────────┘              │  cache_gpoparser_*.json  │
  offline    ┌─────────┐   collect    │  (GPOs, OUs, computers)  │
  dumps   ──▶│ local   │─────────────▶│                          │
            └─────────┘              └──────────┬───────────────┘
                                                │
                            ┌───────────┬───────┴────┬───────────┐
                            ▼           ▼            ▼           ▼
                        display      query        assess      enrich
                     (what it does)(who it hits)(misconfigs)(BloodHound)
```

The cache file defaults to `cache_gpoparser_<timestamp>.json` in the current
directory. The read subcommands auto-pick the **newest** `cache_gpoparser_*.json`
in the working directory when `-c/--cache` is omitted.

## Subcommands

| Subcommand | Connection? | Purpose |
|------------|:-----------:|---------|
| `remote`   | yes | Enumerate and parse GPOs live over LDAP + SYSVOL → cache |
| `local`    | no  | Parse GPOs offline from a local SYSVOL copy + LDAP dump → cache |
| `display`  | no  | Show what GPOs change (groups, privileges, registry, scripts…) |
| `query`    | no  | Map GPOs ⇄ affected computers |
| `assess`   | no* | Flag exploitable GPO misconfigurations |
| `enrich`   | no  | Emit SharpHound-native JSON for BloodHound CE upload |

\* `assess` is offline by default; `--check-acls` makes it connect to AD.

Run `gpoparser <subcommand> --help` for the full per-mode option list.

---

### `remote` — collect from a live DC

Connects to a DC over LDAP to enumerate GPOs, OU/domain links and computers, then
reads each GPO's files from the `SYSVOL` share over SMB and parses them. The result
is written to a JSON cache for `display`/`query`/`assess`/`enrich`.

```sh
# NTLM
gpoparser remote --host dc01.corp.local -d CORP -u jdoe -p 'Passw0rd!'

# Let the password be prompted, write to a named cache
gpoparser remote --host dc01.corp.local -d CORP -u jdoe -p -o corp.json

# LDAPS, pass-the-hash
gpoparser remote --host dc01.corp.local --tls -d CORP -u jdoe \
    --hash aad3b435b51404eeaad3b435b51404ee:...

# Kerberos from an existing ccache (KRB5CCNAME honored automatically)
gpoparser remote --host dc01.corp.local -d CORP -u jdoe -k

# Discover the DC via DNS SRV instead of passing --host
gpoparser remote -d corp.local -u jdoe -p 'Passw0rd!'
```

Options:

| Flag | Description |
|------|-------------|
| `-o, --output` | Output cache file (default `cache_gpoparser_<timestamp>.json`) |

Plus all the [connection / authentication options](#connection--authentication-options).

> SYSVOL access is best-effort: if the SMB read fails, the LDAP metadata and
> link→computer mapping are still cached (GPO *settings* will just be empty).

---

### `local` — collect offline from dumps

Offline analysis. Parses the GPO files in a local `SYSVOL\Policies` copy and, when
an LDAP dump is supplied, resolves GPO names, OU/domain links and the affected
computers. Without `--ldap`, GPOs are discovered from the SYSVOL folder names only
(no link/computer mapping).

```sh
# Full offline analysis from a SYSVOL copy + ldeep dump
gpoparser local --sysvol ./sysvol --ldap ./ldap/dump -f ldeep -o corp.json

# ADExplorer snapshot export (objects.ndjson)
gpoparser local --sysvol ./sysvol --ldap ./objects.ndjson -f adexplorer

# SYSVOL only — discovers GPOs by {GUID} folder name, no targeting
gpoparser local --sysvol ./sysvol
```

Collect the inputs with e.g.:

```sh
mkdir sysvol && cd sysvol && \
  echo -e 'prompt\nrecurse\nmget *' | smbclient //DC/SYSVOL -U user%pass
ldeep ldap -u user -p pass -d corp -s ldap://DC all ./ldap/dump
```

Options:

| Flag | Description |
|------|-------------|
| `--sysvol` | Local `SYSVOL\Policies` directory (**required**) |
| `--ldap` | LDAP dump directory (ldeep) or `objects.ndjson` (ADExplorer) |
| `-f, --format` | `ldeep` \| `adexplorer` (auto-detected if omitted) |
| `-o, --output` | Output cache file (default `cache_gpoparser_<timestamp>.json`) |

This mode takes no connection options.

---

### `display` — what each GPO does

Renders the parsed configuration each GPO applies, split into **Computer** and
**User** configuration: local group membership, privilege rights, registry changes,
system access (password/lockout policy), local users, services, scripts, scheduled
tasks, MSI software installs, mapped drives, file copies, shortcuts, data sources,
printers and environment variables. GPP passwords (`cpassword`) are flagged where
present.

```sh
# Render every GPO in the newest cache
gpoparser display

# A specific cache, filtered to one GPO (GUID or name substring)
gpoparser display -c corp.json -g "Default Domain Policy"

# Machine-readable
gpoparser display --json
```

Options:

| Flag | Description |
|------|-------------|
| `-c, --cache` | Cache file (default: newest `cache_gpoparser_*.json` in cwd) |
| `-g, --gpo` | Filter by GPO GUID or display-name substring |
| `--json` | Emit JSON instead of human-readable output |

---

### `query` — GPO ⇄ computer mapping

Resolves the `gPLink` + OU-inheritance graph.

- With `-g`: lists the computers a GPO applies to.
- With `-C`: lists the GPOs that apply to a computer, in application order
  (least→most specific; later wins), optionally with the settings each one
  contributes (`--settings`).

```sh
# Which computers does this GPO hit?
gpoparser query -g "{31B2F340-016D-11D2-945F-00C04FB984F9}"

# Which GPOs apply to this host, and what do they set?
gpoparser query -C srv01 --settings
```

Options:

| Flag | Description |
|------|-------------|
| `-c, --cache` | Cache file (default: newest `cache_gpoparser_*.json`) |
| `-g, --gpo` | GPO GUID or display-name substring |
| `-C, --computer` | Computer name, DNS name or DN substring |
| `--settings` | Print the settings each applied GPO contributes (`-C` only) |

Exactly one of `-g` / `-C` is required.

---

### `assess` — flag exploitable misconfigurations

Runs an analyser pipeline over a cache and reports exploitable misconfigurations,
sorted most-severe first. Each finding carries the GPO's resolved blast radius
(affected computers). **Offline by default** — it reads only the cache.

With `--check-acls` it additionally connects to AD (and SYSVOL) to flag GPO
objects, policy folders and referenced paths the assessed user can *modify* — a
GPO takeover means code execution on every linked computer.

```sh
# Offline assessment, high+ severity only
gpoparser assess -c corp.json -a high

# Only one finding category, as JSON
gpoparser assess --category gpp-cpassword --json

# Live ACL check: who can take over which GPOs?
gpoparser assess --check-acls --host dc01.corp.local -d CORP -u jdoe -p
```

Options:

| Flag | Description |
|------|-------------|
| `-c, --cache` | Cache file (default: newest `cache_gpoparser_*.json`) |
| `-a, --min-severity` | Minimum severity to report: `info` \| `low` \| `high` \| `critical` (default `low`) |
| `-g, --gpo` | Limit assessment to GPOs matching a GUID or name substring |
| `--category` | Only report findings of this category (see below) |
| `--json` | Emit findings as JSON |
| `--check-acls` | Live-check GPO/SYSVOL/path writability for the connecting user (needs [connection options](#connection--authentication-options)) |

Finding **severities**: `info` < `low` < `high` < `critical`.

Finding **categories** include: `restricted-groups`, `user-rights`,
`system-access`, `registry-policy`, `service-sddl`, `exec-path`, `msi-install`,
`gpp-cpassword`, `gpp-file`, `gpp-shortcut`, `env-var-creds`, and — only with
`--check-acls` — `gpo-object-writable`, `sysvol-writable`, `path-writable`.

---

### `enrich` — feed BloodHound CE

Produces SharpHound-format `<prefix>_ous.json` and `<prefix>_domains.json`
carrying `GPOChanges` (LocalAdmins / RemoteDesktopUsers / DcomUsers / PSRemoteUsers
+ AffectedComputers) for GPO-derived local-group membership. Upload the file(s) in
the BloodHound CE UI (**Administration → File Ingest**); BloodHound creates the
matching `AdminTo` / `CanRDP` / `ExecuteDCOM` / `CanPSRemote` edges, which
participate in pathfinding.

```sh
gpoparser enrich -c corp.json -o corp_bh
# -> corp_bh_ous.json, corp_bh_domains.json
```

Options:

| Flag | Description |
|------|-------------|
| `-c, --cache` | Cache file (default: newest `cache_gpoparser_*.json`) |
| `-o, --output` | Output filename **prefix** (default `gpoparser_bloodhound`) |
| `--schema-version` | SharpHound `meta.version` integer to emit (default `6`) |

> The `meta.version` integer and field shape are version-sensitive across
> BloodHound releases. If ingest is rejected, compare against a sample produced by
> your BloodHound CE instance's own collector and adjust `--schema-version`.

---

## Connection / authentication options

Used by `remote`, and by `assess --check-acls`. Shared with the rest of the adtools
suite.

### Connection

| Flag | Description |
|------|-------------|
| `--host` | DC hostname or IP (required; hostname for Kerberos). If omitted but `-d/--domain` is a FQDN, the DC is discovered via DNS SRV. |
| `-P, --port` | LDAP port (default 389, or 636 with `--tls`) |
| `--tls` | Use LDAPS (implicit TLS) |
| `--starttls` | Use StartTLS on the plain LDAP port |
| `--insecure` | Skip TLS certificate verification |
| `--base-dn` | Search base DN (auto-detected from RootDSE if omitted) |
| `--sasl` | SASL security: `none`, `sign`, `seal` |
| `--channel` | Enable TLS channel binding (requires `--tls`/`--starttls`) |
| `--smb-port` | SMB port for SYSVOL (default 445) |
| `--noenc` | Disable SMB encryption when reading SYSVOL |
| `--smb2` | Force SMB 2.1 for SYSVOL access |
| `-t, --timeout` | Dial timeout (e.g. `5s`, `1m`; default `5s`) |
| `--socks-host` / `--socks-port` | SOCKS5 proxy (default port 1080) |

### Authentication

NTLM is the default. Use `--simple`/`--anonymous` for simple binds or
`-k`/`--kerberos` (or `--keytab-file`) for Kerberos.

| Flag | Description |
|------|-------------|
| `-d, --domain` | AD domain (e.g. `CORP`) |
| `-u, --user` | Username (or full DN with `--simple`) |
| `-p, --pass` | Password. Bare `-p` prompts on terminal. |
| `--hash` | NT hash (pass-the-hash / Kerberos RC4) |
| `-n, --no-pass` | Send no password (unauthenticated bind) |
| `--simple` | LDAP simple bind (DN/password; requires `--tls`/`--starttls`) |
| `--anonymous` | LDAP simple anonymous bind (no creds) |

### Kerberos (with `-k` / `--kerberos`)

| Flag | Description |
|------|-------------|
| `-k, --kerberos` | Use Kerberos (GSSAPI) instead of NTLM |
| `--keytab-file` | Authenticate with a Kerberos keytab (implies `-k`; principal/realm read from the keytab when `--user`/`--domain` are omitted) |
| `--ccache` | Kerberos credential cache file (falls back to `$KRB5CCNAME`) |
| `--krb5conf` | Path to krb5.conf (default `/etc/krb5.conf`) |
| `--realm` | Kerberos realm (defaults to upper-cased `--domain`) |
| `--aes-key` | Hex AES128/256 key |
| `--override-spn` | LDAP SPN (default `ldap/<host>`) |
| `--dc-ip` | KDC address override (`ip[:port]`, default port 88) |
| `--target-ip` | IP to connect to; skips DNS of `--host` |
| `--dns-host` | Override system DNS resolver (`ip[:port]`, default port 53) |
| `--dns-tcp` | Force DNS lookups over TCP |

### Diagnostics

| Flag | Description |
|------|-------------|
| `--debug` | Debug logging. Bare `--debug` targets every package; `--debug=smb,ldap` filters to the listed package-name suffixes (the `=` form is required). |
| `--verbose` | Verbose logging. Same filter syntax as `--debug`. |
| `--list-log-packages` | List the registered log package names targetable by `--debug=`/`--verbose=`, then exit |
| `-v, --version` | Print version and linked module versions |

`SSLKEYLOGFILE` is honored for TLS key logging (Wireshark decryption).
