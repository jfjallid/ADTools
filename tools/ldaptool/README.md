# LdapTool

A Go CLI for LDAP enumeration and post-exploitation against Active Directory.
Supports search and modify, user/computer creation, SPN management, Shadow
Credentials (`msDS-KeyCredentialLink`), Resource-Based Constrained Delegation,
group membership editing, LAPS password reads, and signing / channel-binding
detection. Includes an interactive shell.

Bind methods: NTLM (default), Kerberos (GSSAPI), LDAP simple, anonymous.
Transport: plain LDAP, LDAPS, StartTLS, optionally tunneled through SOCKS5.
Pass-the-hash (`--hash`) and pass-the-key (`--aes-key`) supported.

## Build
```sh
make
```

## Usage

```bash
ldaptool <subcommand> [options]
ldaptool <subcommand> --help
ldaptool --version
```

| Subcommand               | Description                                                |
|--------------------------|------------------------------------------------------------|
| `search`                 | Search for LDAP objects                                    |
| `modify`                 | Modify attributes on an LDAP object                        |
| `delete-object`          | Delete an LDAP object by DN                                |
| `create-user`            | Create a new user account                                  |
| `create-computer`        | Create a new computer account                              |
| `spn`                    | Manage `servicePrincipalName` on an object                 |
| `shadow-credentials`     | Manage `msDS-KeyCredentialLink` (Shadow Credentials)       |
| `rbcd`                   | Manage `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD)   |
| `group`                  | Add or remove group members                                |
| `laps`                   | Read LAPS local-admin passwords                            |
| `detect-signing`         | Detect if LDAP signing is required                         |
| `detect-channel-binding` | Detect if LDAP channel binding is required                 |
| `shell`                  | Launch interactive shell                                   |

## Connection and authentication options

These flags apply to every subcommand.

### Connection

| Flag                  | Description                                        |
|-----------------------|----------------------------------------------------|
|     `--host`          | DC hostname or IP (required, or use `--domain` for SRV-based DC discovery) |
| `-P, --port`          | LDAP port (default: 389, or 636 with `--tls`)      |
|     `--tls`           | Use LDAPS (implicit TLS)                           |
|     `--starttls`      | Use StartTLS on plain LDAP port                    |
|     `--insecure`      | Skip TLS certificate verification                  |
|     `--base-dn`       | Search base DN (auto-detected from RootDSE if omitted) |
|     `--naming-context`| `default` \| `configuration` \| `schema` \| `root` (default: `default`) |
|     `--sasl`          | SASL security: `none` \| `sign` \| `seal` (default: `seal` on plain LDAP, `none` on TLS) |
|     `--channel`       | Enable TLS channel binding                         |
| `-t, --timeout`       | Dial timeout (default: 5s)                         |
|     `--socks-host`    | SOCKS5 proxy host                                  |
|     `--socks-port`    | SOCKS5 proxy port (default: 1080)                  |

### Authentication

NTLM is used unless `--simple`, `--anonymous`, or `--kerberos` is given.

| Flag                  | Description                                        |
|-----------------------|----------------------------------------------------|
| `-d, --domain`        | AD domain (e.g. `CORP`)                            |
| `-u, --user`          | Username (or full DN with `--simple`)              |
| `-p, --pass`          | Password (or set `AD_PASSWORD` env var). If empty, prompts on terminal. |
|     `--hash`          | NT hash (pass-the-hash for NTLM, RC4 key for Kerberos) |
| `-n, --no-pass`       | Send no password (unauthenticated NTLM bind)       |
|     `--simple`        | LDAP simple bind (DN/password). Refuses cleartext without TLS unless `--sasl=none`. |
|     `--anonymous`     | LDAP simple anonymous bind (no credentials)        |

### Kerberos

| Flag             | Description                                                   |
| ---------------- | ------------------------------------------------------------- |
| `-k, --kerberos` | Use Kerberos (GSSAPI) instead of NTLM                         |
| `--ccache`       | Path to credential cache (falls back to `$KRB5CCNAME`)        |
| `--krb5conf`     | Path to `krb5.conf` (default: `/etc/krb5.conf`)               |
| `--realm`        | Kerberos realm (defaults to upper-cased `--domain`)           |
| `--aes-key`      | Hex AES128/256 key                                            |
| `--override-spn` | Service principal name (default: `ldap/<host>`)               |
| `--dc-ip`        | KDC address override (`host[:port]`, default port 88)         |
| `--dns-host`     | Override system DNS resolver (`host[:port]`, default port 53) |
| `--dns-tcp`      | Force DNS lookups over TCP                                    |

### Diagnostics

| Flag            | Description            |
| --------------- | ---------------------- |
| `--debug`       | Enable debug logging   |
| `--verbose`     | Enable verbose output  |
| `-v, --version` | Print version and exit |

## Subcommands

### `search` — Search for LDAP objects

| Flag               | Description                                                                                                                                                      |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--filter`         | LDAP filter (default: `(objectClass=*)`)                                                                                                                         |
| `--preset`         | Canned filter (overrides `--filter`): `kerberoastable`, `asreproastable`, `admins`, `dcs`, `computers`, `machine-accounts`,<br>`trusts`, `gpos`, `unconstrained` |
| `--search-base`    | Override search base DN                                                                                                                                          |
| `--scope`          | `base` \| `one` \| `sub` (default: `sub`)                                                                                                                        |
| `--page-size`      | Page size, 0 disables paging (default: 1000)                                                                                                                     |
| `--size-limit`     | Server-side size limit, 0 = unlimited (default: 0)                                                                                                               |
| `--time-limit`     | Server-side time limit (seconds), 0 = unlimited                                                                                                                  |
| `--attrs`          | Comma-separated attrs. `*` = all user attrs; `*,<op-attr>` to add specific operational attrs (default: `*`)                                                      |
| `--ldif`           | Emit LDIF output                                                                                                                                                 |
| `--json`           | Emit JSON output                                                                                                                                                 |
| `--control`        | Search control (repeatable): `show-deleted`, `server-sort=[+\|-]<attr>[:matchingOid]`                                                                            |
| `--no-banner`      | Suppress effective-request banner                                                                                                                                |
| `--no-schema-hint` | Skip schema lookup for unknown octet-string attrs                                                                                                                |
| `--out-file`       | Write output to file                                                                                                                                             |

```sh
ldaptool search --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --preset kerberoastable --attrs sAMAccountName,servicePrincipalName
```

### `modify` — Modify attributes on an LDAP object

| Flag       | Description                                                 |
| ---------- | ----------------------------------------------------------- |
| `--dn`     | DN of the object to modify (required)                       |
| `--set`    | Replace attribute: `name=value` (repeatable)                |
| `--add`    | Add attribute value: `name=value` (repeatable)              |
| `--delete` | Delete attribute value: `name=value` or `name` (repeatable) |

Any value may be given as `@<path>` to load it from a file, useful for binary
attributes (DACLs, certificates).

```sh
ldaptool modify --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --dn 'CN=svc,CN=Users,DC=corp,DC=local' \
    --set 'description=temporary'
```

### `delete-object` — Delete an LDAP object by DN

| Flag   | Description                           |
| ------ | ------------------------------------- |
| `--dn` | DN of the object to delete (required) |

The DN must be a leaf (no children) unless the directory permits subtree
deletion. Subtree deletion is not performed.

```sh
ldaptool delete-object --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --dn 'CN=stale-host,CN=Computers,DC=corp,DC=local'
```

### `create-user` — Create a new user account

| Flag              | Description                                             |
| ----------------- | ------------------------------------------------------- |
| `--cn`            | Common name / display name (required)                   |
| `--sam`           | `sAMAccountName` (required)                             |
| `--ou`            | OU DN to create user in (default: `CN=Users,<base-dn>`) |
| `--upn`           | `userPrincipalName`                                     |
| `--given-name`    | First name                                              |
| `--sn`            | Last name                                               |
| `--description`   | Description                                             |
| `--user-password` | Initial password (requires LDAPS or StartTLS)           |
| `--enabled`       | Enable the account (default: disabled)                  |

```sh
ldaptool create-user --host dc.corp.local --tls -d CORP -u alice -p Passw0rd! \
    --cn 'Bob Tester' --sam btester --user-password 'TempPass!23' --enabled
```

### `create-computer` — Create a new computer account

| Flag                | Description                                                           |
| ------------------- | --------------------------------------------------------------------- |
| `--cn`              | Computer name without trailing `$` (required)                         |
| `--ou`              | OU DN (default: `CN=Computers,<base-dn>`)                             |
| `--description`     | Description                                                           |
| `--managed-by`      | DN of managing user/group                                             |
| `--password`        | Initial password (random 24-char if omitted; requires LDAPS/StartTLS) |
| `--computer-domain` | Computer domain name for SPNs (default: `--domain`)                   |

```sh
ldaptool create-computer --host dc.corp.local --tls -d CORP -u alice -p Passw0rd! \
    --cn pwn1
```

### `spn` — Manage `servicePrincipalName`

| Flag        | Description                                         |
| ----------- | --------------------------------------------------- |
| `--dn`      | DN of the object to set SPNs on (required)          |
| `--add`     | SPN to add (repeatable, e.g. `HTTP/app.corp.local`) |
| `--remove`  | SPN to remove (repeatable)                          |
| `--replace` | Replace all SPNs with these values (repeatable)     |

```sh
ldaptool spn --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --dn 'CN=svc,CN=Users,DC=corp,DC=local' --add HTTP/app.corp.local
```

### `shadow-credentials` — Manage `msDS-KeyCredentialLink`

| Flag          | Description                                       |
| ------------- | ------------------------------------------------- |
| `--action`    | `add` \| `list` \| `remove` \| `clear` (required) |
| `--target`    | `sAMAccountName` of target account (required)     |
| `--device-id` | Device ID to remove (for `remove` action)         |
| `--out`       | Output PFX file path (default: `<target>.pfx`)    |
| `--pfx-pass`  | PFX file password (default: empty)                |

`add` generates an RSA key pair and self-signed certificate, links it to the
target account, and exports a PFX usable for PKINIT.

```sh
ldaptool shadow-credentials --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --action add --target victim --out victim.pfx
```

### `rbcd` — Manage Resource-Based Constrained Delegation

Edits the target's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.

| Flag        | Description                                                                       |
| ----------- | --------------------------------------------------------------------------------- |
| `--action`  | `add` \| `list` \| `remove` \| `clear` (required)                                 |
| `--target`  | `sAMAccountName` of the resource being delegated TO (required)                    |
| `--trustee` | SID or `sAMAccountName` allowed to delegate (required for add/remove; repeatable) |

```sh
ldaptool rbcd --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --action add --target 'victim$' --trustee 'attacker$'
```

### `group` — Add or remove group members

| Flag       | Description                                                  |
| ---------- | ------------------------------------------------------------ |
| `--action` | `add` or `remove` (required)                                 |
| `--group`  | Group, by DN or `sAMAccountName` (required)                  |
| `--member` | Member to add/remove, by DN or `sAMAccountName`. Repeatable. |

```sh
ldaptool group --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --action add --group 'Domain Admins' --member btester
```

### `laps` — Read LAPS local-admin passwords

Searches for computers with one of:

- `ms-Mcs-AdmPwd` — legacy "Microsoft LAPS"
- `msLAPS-Password` — Windows LAPS, plaintext
- `msLAPS-EncryptedPassword` — Windows LAPS, DPAPI-NG protected (reported but not decrypted; decryption requires DPAPI-NG with a domain protector key)

| Flag       | Description                                                                                       |
| ---------- | ------------------------------------------------------------------------------------------------- |
| `--target` | Limit to a single computer by `sAMAccountName`. If omitted, returns all readable LAPS attributes. |

```sh
ldaptool laps --host dc.corp.local -d CORP -u alice -p Passw0rd! --target WS01
```

### `detect-signing` — Detect if LDAP signing is required

No subcommand-specific flags. Probes whether the DC enforces LDAP signing
by performing an unsigned bind over plaintext LDAP and watching for
`strongerAuthRequired`. Credentials are required. Plain LDAP only — fails
if `--tls` or `--starttls` is set.

```sh
ldaptool detect-signing --host dc.corp.local -d CORP -u alice -p Passw0rd!
```

### `detect-channel-binding` — Detect if LDAP channel binding is required

No subcommand-specific flags. Performs an NTLM or Kerberos bind without
channel binding over TLS and classifies the response. Forces `--tls`;
`--starttls` is also acceptable.

```sh
ldaptool detect-channel-binding --host dc.corp.local --tls \
    -d CORP -u alice -p Passw0rd!
```

### `shell` — Launch interactive shell

| Flag           | Description                                                                             |
| -------------- | --------------------------------------------------------------------------------------- |
| `--no-history` | Disable command history file (`$LDAPTOOL_HISTORY` or `~/.ldaptool_history`, 1000 lines) |

The connection options are used for the initial bind; once inside, `connect`
and `login` / `login_krb` can open new connections.

```sh
ldaptool shell --host dc.corp.local -d CORP -u alice -p Passw0rd!
```

#### Interactive commands

| Command            | Description                                                  |
|--------------------|--------------------------------------------------------------|
| `help`, `?`        | Show available commands                                      |
| `connect`          | Open a new LDAP connection (no auth)                         |
| `login`            | Authenticate with NTLM (prompts for password if not given)   |
| `login_krb`        | Authenticate with Kerberos                                   |
| `logout`           | Close current connection                                     |
| `reconnect`        | Re-establish the current connection                          |
| `tls`              | Upgrade plain connection via StartTLS                        |
| `setbasedn <dn>`   | Set working base DN for searches                             |
| `toggleverbose`    | Toggle verbose output                                        |
| `togglebanner`     | Toggle effective-request banner                              |
| `describe`         | Describe an LDAP attribute (schema lookup)                   |
| `search`           | Search for LDAP objects (same flags as the `search` subcommand) |
| `modify`           | Modify attributes (same flags as the `modify` subcommand)    |
| `deleteobject`     | Delete an LDAP object                                        |
| `createuser`       | Create a new AD user                                         |
| `createcomputer`   | Create a new AD computer                                     |
| `spn`              | Manage `servicePrincipalName`                                |
| `shadowcreds`      | Manage `msDS-KeyCredentialLink`                              |
| `rbcd`             | Manage RBCD                                                  |
| `group`            | Add or remove group members                                  |
| `laps`             | Read LAPS passwords                                          |
| `exit`             | Leave the shell                                              |

## Environment variables

| Variable             | Purpose                                                         |
|----------------------|-----------------------------------------------------------------|
| `AD_PASSWORD`        | Fallback password when `--pass` is not supplied                 |
| `KRB5CCNAME`         | Default Kerberos credential cache (used if `--ccache` is empty) |
| `LDAPTOOL_HISTORY`   | Shell history file path (default: `~/.ldaptool_history`)        |
| `SSLKEYLOGFILE`      | TLS key log file path (for packet decryption while debugging)   |
