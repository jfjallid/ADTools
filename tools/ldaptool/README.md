# LdapTool

A Go CLI for LDAP enumeration and post-exploitation against Active Directory.
Supports search and modify, object deletion, user/computer creation, password
set/reset, SPN management, Shadow Credentials (`msDS-KeyCredentialLink`),
Resource-Based Constrained Delegation, DACL and owner editing on security
descriptors, effective-access computation, group membership editing, LAPS
password reads, and signing / channel-binding detection. Includes an
interactive shell.

Bind methods: NTLM (default), Kerberos (GSSAPI), LDAP simple, anonymous.
Transport: plain LDAP, LDAPS, StartTLS, optionally tunneled through SOCKS5.
Pass-the-hash (`--hash`), pass-the-key (`--aes-key`), and keytab
(`--keytab-file`) authentication supported.

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
| `set-password`           | Set or change an account's password (`unicodePwd`)         |
| `spn`                    | Manage `servicePrincipalName` on an object                 |
| `shadow-credentials`     | Manage `msDS-KeyCredentialLink` (Shadow Credentials)       |
| `rbcd`                   | Manage `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD)   |
| `dacl`                   | View and modify DACLs on object security descriptors       |
| `owner`                  | View and change the owner SID of a security descriptor     |
| `access`                 | Compute a principal's effective access to an object        |
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
| `-p, --pass`          | Password. If empty, prompts on terminal. |
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
| `--keytab-file`  | Authenticate from a Kerberos keytab (implies `-k`; principal and realm default to the keytab's first entry, overridable with `--user` and `--realm`/`--domain`) |
| `--override-spn` | Service principal name (default: `ldap/<host>`)               |
| `--dc-ip`        | KDC address override for Kerberos (`host[:port]`, default port 88) |
| `--target-ip`    | IP to connect to for LDAP; skips DNS resolution of `--host`   |
| `--dns-host`     | Override system DNS resolver (`host[:port]`, default port 53) |
| `--dns-tcp`      | Force DNS lookups over TCP                                    |

### Diagnostics

| Flag                  | Description                                                                                                                                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--debug`             | Enable debug logging. Bare `--debug` turns on every registered package; `--debug=ldap,smb` filters to the listed package-name suffixes (the `=` form is required). |
| `--verbose`           | Enable verbose output. Same filter syntax as `--debug`; the two may be combined with different filters (a package targeted by both gets the higher level).    |
| `--list-log-packages` | List the registered log package names targetable by `--debug=<suffix>` / `--verbose=<suffix>`, then exit                                                      |
| `-v, --version`       | Print version and exit                                                                                                                                       |

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

### `set-password` — Set or change an account's password

Writes `unicodePwd` on an existing account. The target may be a
`sAMAccountName` or a full DN. Like the create actions, this needs a
confidential connection (`--tls`, `--starttls`, or `--sasl seal`).

| Flag             | Description                                                              |
| ---------------- | ------------------------------------------------------------------------ |
| `--target`       | `sAMAccountName` or DN of the account (required)                         |
| `--reset`        | Administrative reset (overwrite); needs only the new password            |
| `--new-password` | New password (prompted if omitted)                                       |
| `--old-password` | Current password, for a change (prompted if omitted unless `--reset`)    |

The default mode is a **self-service change** (requires only the
Change-Password right): you must prove the current password, and any of
`--old-password` / `--new-password` not given on the command line is prompted
for. Pass `--reset` for an **administrative reset** (requires the
Reset-Password right), which overwrites the password and needs only the new
one.

```sh
# Administrative reset (overwrite):
ldaptool set-password --host dc.corp.local --tls -d CORP -u admin -p Passw0rd! \
    --reset --target victim --new-password 'NewP@ss1!'

# Self-service change (prompts for the current and new password):
ldaptool set-password --host dc.corp.local --tls -d CORP -u victim -p - \
    --target victim
```

In the interactive shell the command is `set-password` (flags use single dashes
and the password flags are abbreviated, e.g.
`set-password -reset -target victim -newpass 'NewP@ss1!'`).

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
| `--pfx-pass`  | PFX file password (default: randomly generated)   |
| `--no-pfx-pass` | Use an empty PFX password instead of generating one |

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
| `--action`   | `add` \| `list` \| `remove` \| `clear` (required)                                 |
| `--target`   | `sAMAccountName` of the resource being delegated TO (required)                    |
| `--trustee`  | SID or `sAMAccountName` allowed to delegate (required for add/remove; repeatable) |
| `--dry-mode` | Do not write; print the security-descriptor bytes that would be set (only valid with `--action add`) |

```sh
ldaptool rbcd --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --action add --target 'victim$' --trustee 'attacker$'
```

### `dacl` — View and modify object DACLs

Reads and edits the discretionary ACL (DACL) of an object's `nTSecurityDescriptor`.
Permissions are translated to friendly names; object ACEs (extended rights such
as DCSync and ResetPassword, and per-property writes) are fully supported.

| Flag                      | Description                                                                 |
| ------------------------- | --------------------------------------------------------------------------- |
| `--action`                | `read` \| `add` \| `remove` \| `backup` \| `restore` (required)             |
| `--target`                | Object to operate on: `sAMAccountName`, DN, or SID (required)               |
| `--trustee`               | Principal the ACE applies to: `sAMAccountName`, DN, or SID (add/remove)      |
| `--rights`                | Named preset (repeatable): `FullControl`, `DCSync`, `ResetPassword`, `WriteMembers`, `AllExtendedRights`, `WriteDacl`, `WriteOwner` |
| `--mask`                  | Raw `ACCESS_MASK`, hex (`0x..`) or decimal                                  |
| `--right-guid`            | Extended-right/property GUID for an object ACE (repeatable)                 |
| `--ace-type`              | `allowed` or `denied` (default `allowed`)                                   |
| `--inheritance`           | Set `CONTAINER_INHERIT_ACE` on added ACEs (AD's inheritance flag)            |
| `--inherit-only`          | Set `INHERIT_ONLY_ACE`; the ACE applies to children only, not the target. Requires `--inheritance` |
| `--ace-flags`             | Raw ACE flags byte (hex `0x..` or decimal), e.g. `0x0A`; alternative to `--inheritance`/`--inherit-only` (mutually exclusive) |
| `--inherited-object-guid` | Schema GUID for `INHERITED_OBJECT_TYPE`: scope inheritance to one descendant class (e.g. computer = `bf967a86-0de6-11d0-a285-00aa003049e2`) |
| `--resolve-sids`          | Resolve SIDs to names in `read` output                                      |
| `--file`                  | File path for `backup`/`restore` (base64 of the raw descriptor)             |

Reads request `OWNER|GROUP|DACL` via the SD-flags control (no `SeSecurityPrivilege`
needed); writes are scoped to the DACL so owner/group/SACL are left untouched.
When the target is the domain object itself, `read` also flags any principal
whose ACEs effectively grant DCSync (the replication rights only apply there).

For `remove`, an ACE matches on trustee, type, mask, and the object GUIDs
(`--right-guid` / `--inherited-object-guid`). ACE flags are ignored by default,
so a grant is removed regardless of its inheritance settings; passing any of
`--inheritance`/`--inherit-only`/`--ace-flags` additionally requires an exact
ACE-flags match (e.g. to remove the inherit-only copy and leave others).

```sh
# Grant FullControl to all descendant computer objects under a container
ldaptool dacl --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --action add --target 'CN=Computers,DC=corp,DC=local' --trustee svc01 \
    --rights FullControl --inheritance --inherit-only \
    --inherited-object-guid bf967a86-0de6-11d0-a285-00aa003049e2
```

```sh
# View a DACL with permissions and SIDs resolved
ldaptool dacl --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --action read --target krbtgt --resolve-sids

# Grant a principal DCSync on the domain
ldaptool dacl --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --action add --target CORP --trustee attacker --rights DCSync

# Grant ResetPassword over a user, then remove just that ACE
ldaptool dacl ... --action add    --target bob --trustee attacker --rights ResetPassword
ldaptool dacl ... --action remove --target bob --trustee attacker --rights ResetPassword
```

### `owner` — View and change a security descriptor's owner

Reads and changes the Owner SID of an object's `nTSecurityDescriptor` (cf.
impacket's `owneredit.py`). This matters because the owner of an AD object holds
an implicit, irrevocable `WRITE_DAC` right over it regardless of the DACL: an
attacker with `WriteOwner` over a target can take ownership and then rewrite the
DACL to grant themselves an abusable right (DCSync, ResetPassword, …). Backing
up and restoring the owner is the corresponding remediation.

| Flag             | Description                                                    |
| ---------------- | -------------------------------------------------------------- |
| `--action`       | `read` \| `set` \| `backup` \| `restore` (required)            |
| `--target`       | Object to operate on: `sAMAccountName`, DN, or SID (required)  |
| `--owner`        | New owner: `sAMAccountName`, DN, or SID (required for `set`)    |
| `--file`         | File path for `backup`/`restore` (stores the owner SID)        |
| `--resolve-sids` | Resolve SIDs to names in `read` output                         |

Writes are scoped to the owner via the SD-flags control, so the DACL, group, and
SACL are left untouched.

```sh
# Read the current owner, names resolved
ldaptool owner --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --action read --target dc01 --resolve-sids

# Back up, take ownership, then later restore
ldaptool owner ... --action backup  --target victim --file victim.owner
ldaptool owner ... --action set     --target victim --owner attacker
ldaptool owner ... --action restore --target victim --file victim.owner
```

### `access` — Compute a principal's effective access

Answers "what can this security principal actually do to this object?" — the
equivalent of the Windows *Advanced Security Settings → Effective Access* tab.
It builds the principal's token (its own SID plus the full transitive set of
group SIDs the DC reports via the `tokenGroups` constructed attribute — nested
groups, primary group, and `sIDHistory` — plus the assumed session SIDs), then
runs the canonical NT access check against the target's (already
inheritance-flattened) DACL and maps the result to friendly rights. Object
ownership's implicit `READ_CONTROL`/`WRITE_DAC` is accounted for (and the
`OWNER_RIGHTS` override honoured).

| Flag                | Description                                                                  |
| ------------------- | ---------------------------------------------------------------------------- |
| `--target`          | Object to evaluate: `sAMAccountName`, DN, or SID (required)                   |
| `--principal`       | Security principal to evaluate: `sAMAccountName`, DN, or SID (required)       |
| `--right`           | Ask only about a specific right (repeatable); default prints a full report   |
| `--no-session-sids` | Do not assume `Everyone` / `Authenticated Users` / `This Organization`       |
| `--show-token`      | Print the expanded SID set used for the check                                |

`--right` accepts a preset (`FullControl`, `DCSync`, `ResetPassword`, …), a
mask-bit name (`WriteProperty`, `WriteDacl`, `GenericAll`, …), an extended-right
or property GUID, or `write:<attr>` / `read:<attr>` (attribute
`lDAPDisplayName` or GUID). A bare attribute name reports **both** read and
write.

Limitations mirror the Windows tab itself: privileges (`SeBackup`/`SeRestore`/
`SeTakeOwnership`), logon-type SIDs, and conditional/claims ACEs are not
modelled; property-*set* ACEs are reported by set without member expansion.

```sh
# Full effective-access report for a principal on a DC object
ldaptool access --host dc.corp.local -d CORP -u alice -p Passw0rd! \
    --target dc01 --principal helpdesk

# Single question: can 'bob' write the SPN attribute on dc01 (direct or via groups)?
ldaptool access ... --target dc01 --principal bob --right write:servicePrincipalName

# Can 'bob' DCSync the domain?
ldaptool access ... --target CORP --principal bob --right dcsync
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
| `set-password`     | Set or change an account's password (`unicodePwd`)           |
| `spn`              | Manage `servicePrincipalName`                                |
| `shadowcreds`      | Manage `msDS-KeyCredentialLink`                              |
| `rbcd`             | Manage RBCD                                                  |
| `dacl`             | View and modify object DACLs                                 |
| `owner`            | View and change a security descriptor's owner               |
| `access`           | Compute a principal's effective access to an object         |
| `group`            | Add or remove group members                                  |
| `laps`             | Read LAPS passwords                                          |
| `exit`             | Leave the shell                                              |

## Environment variables

| Variable             | Purpose                                                         |
|----------------------|-----------------------------------------------------------------|
| `KRB5CCNAME`         | Default Kerberos credential cache (used if `--ccache` is empty) |
| `LDAPTOOL_HISTORY`   | Shell history file path (default: `~/.ldaptool_history`)        |
| `SSLKEYLOGFILE`      | TLS key log file path (for packet decryption while debugging)   |
