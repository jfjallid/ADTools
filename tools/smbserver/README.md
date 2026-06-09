# smbserver

A standalone SMB server built on the server side of
[`go-smb`](https://github.com/jfjallid/go-smb). It serves disk- and
memory-backed shares, and — more usefully for offensive work — captures the
NTLM authentications that clients send to it. Every `AUTHENTICATE` is logged in
hashcat-ready Net-NTLMv2 format, so the server doubles as a credential-dumping
landing point for coercion (see `rpctrigger`), spoofed UNC paths, broadcast
poisoning, or any other technique that drives a victim to authenticate to a
host you control.

It supports SMB 2.0.2 through 3.1.1, SMB3 encryption and signing, NTLM
authentication against a configured account list (password or NT hash), guest
and anonymous sessions, per-share write control, an IP whitelist, and a
hardcoded NTLM server challenge for offline cracking. Configuration comes from
a YAML file, CLI flags, or both — **CLI flags override any field set in the
config file.**

## Build

```sh
make -C tools/smbserver     # builds ./tools/smbserver/smbserver
# or from the repo root:
make                        # builds all tools into bin/
```

## Usage

```sh
smbserver [options]
smbserver --config server.yaml
smbserver --version
```

The simplest credential-capture invocation needs nothing more than the dump
flag (binding to `:445` requires root or `CAP_NET_BIND_SERVICE`):

```sh
sudo smbserver --dump-creds
```

A server with no accounts, guest, or anonymous access **and** no credential
capture is refused at startup — there would be nothing it could do. Enabling
`--dump-creds` is enough on its own (auth always "fails", but the hash is
captured first).

## Configuration model

There are two ways to configure the server, and they compose:

1. A YAML config file passed with `--config`. Unknown fields are rejected.
2. CLI flags, which are layered on top of the file (or on top of the built-in
   defaults if no file is given).

Only flags you **explicitly set** override the file. For the list-valued
options — `--share`, `--account`, `--allow-ip` — supplying the flag on the CLI
**replaces** the entire corresponding list from the config file rather than
appending to it.

See [`example.yaml`](./example.yaml) for a fully populated config.

### Defaults

| Setting          | Default       |
|------------------|---------------|
| Listen address   | `:445`        |
| NetBIOS name     | `GO-SMB`      |
| NetBIOS domain   | `WORKGROUP`   |
| Min dialect      | `2.0.2`       |
| Max dialect      | `3.1.1`       |
| Encryption       | supported, not required |
| Signing          | not required  |
| Guest / anonymous| disabled      |

## CLI options

### General

| Flag              | Config field | Description |
|-------------------|--------------|-------------|
| `--config <path>` | —            | YAML config file to load first |
| `-b, --bind <addr>` | `listen`   | Listen address (default `:445`) |
| `-v, --version`   | —            | Print version and linked module versions |

### SMB protocol

| Flag                      | Config field          | Description |
|---------------------------|-----------------------|-------------|
| `--min-dialect <ver>`     | `dialects.min`        | Lowest dialect to negotiate: `2.0.2`, `2.1`, `3.0`, `3.0.2`, `3.1.1` |
| `--max-dialect <ver>`     | `dialects.max`        | Highest dialect to negotiate (must be ≥ min) |
| `--no-encryption`         | `encryption.supported`| Do not advertise SMB3 encryption capability (default: advertised) |
| `--require-encryption`    | `encryption.required` | Force every session into encrypted mode (SMB 3.1.1 only); implies encryption supported |
| `--require-signing`       | `signing.required`    | Advertise that message signing is required |
| `--netbios-name <name>`   | `netbios.name`        | Advertised NetBIOS server name (default `GO-SMB`) |
| `--netbios-domain <name>` | `netbios.domain`      | Advertised NetBIOS / NTLM domain (default `WORKGROUP`) |
| `--dns-name <fqdn>`       | `netbios.dns_name`    | Advertised DNS computer name |
| `--dns-domain <name>`     | `netbios.dns_domain`  | Advertised DNS domain name |
| `--ntlm-challenge <hex>`  | —                     | Hardcode the 8-byte server challenge (see below) |

The advertised NetBIOS/DNS names appear in the NTLM `CHALLENGE` target
information. The NetBIOS domain also becomes the default domain for any
configured accounts.

### Sessions

| Flag                | Config field              | Description |
|---------------------|---------------------------|-------------|
| `--allow-guest`     | `sessions.allow_guest`    | Permit guest sessions when authentication fails |
| `--allow-anonymous` | `sessions.allow_anonymous`| Permit null (anonymous) sessions |

### Shares (repeatable)

```
--share name=Public,backend=disk,path=/srv/pub,readonly=true,encrypt=false
--share name=Drop,backend=memory
```

Each `--share` defines one share. The full key set:

| Key                     | Meaning |
|-------------------------|---------|
| `name`                  | Share name (required; `IPC$` is reserved and rejected) |
| `backend`               | `disk` or `memory` (CLI defaults to `disk` if omitted) |
| `path`                  | Filesystem root — required for `disk`, rejected for `memory` (disk falls back to the current directory if omitted on the CLI) |
| `readonly`              | Kill switch: nobody can write. Mutually exclusive with the write keys below |
| `encrypt`              | Require SMB3 encryption for this share specifically |
| `writable_users`        | Pipe-separated list of accounts allowed to write, e.g. `alice|bob`. Empty = all authenticated users can write |
| `allow_anonymous_write` | Allow null sessions to write (also needs global `--allow-anonymous`) |
| `allow_guest_write`     | Allow guest sessions to write (also needs global `--allow-guest`) |

> **Write-default asymmetry:** a share defined on the **CLI** allows anonymous
> and guest writes by default (unless `readonly=true`); a share defined in
> **YAML** does not (the booleans default to `false`). Set the keys explicitly
> if you care.

- `backend=memory` shares are always writable (the in-memory VFS has no
  read-only mode) — `readonly=true` is rejected for them.
- Anyone who can connect can **read** a share; the write keys only gate writes.

### Accounts (repeatable)

```
--account user=alice,domain=WORKGROUP,password=secret
--account user=bob,nthash=36AA83BDCAB3C9FDAF321CA42A31C3FC
```

| Key        | Meaning |
|------------|---------|
| `user`     | Username (required) |
| `domain`   | Account domain (optional; see single-domain note) |
| `password` | Cleartext password — exactly one of `password`/`nthash` required |
| `nthash`   | 32-hex-char NT hash (pass-the-hash style) — the other of the pair |

> **Single domain only:** the underlying `MapAuthenticator` supports one domain.
> The first account with a non-empty `domain` sets it; every other account must
> match that domain or leave `domain` empty (empty is treated as the chosen
> domain). If no account specifies a domain, the NetBIOS domain is used.

### Credential dumping

| Flag               | Config field         | Description |
|--------------------|----------------------|-------------|
| `--dump-creds`     | `credentials.dump`   | Log every captured NTLM `AUTHENTICATE` as a hashcat Net-NTLMv2 line |
| `--cred-log <path>`| `credentials.log_file` | Append captured hashcat lines to a file (created mode `0600`) |

When capture is on, each authentication attempt prints a `[+] captured ...`
notice with the source IP, account, and workstation, plus the hashcat string
(to the log file if configured, otherwise to stdout). A separate
success/failure line is logged per attempt via the authenticator. The hash is
captured **before** verification, so it is recorded even when authentication
ultimately fails (the usual case for a pure capture server).

The captured Net-NTLMv2 line is hashcat mode **5600**:

```sh
hashcat -m 5600 captured.txt wordlist.txt
```

### `--ntlm-challenge`

Hardcodes the 8-byte server challenge (16 hex chars) that the server sends in
its NTLM `CHALLENGE` message instead of a random one, for example:

```sh
smbserver --dump-creds --ntlm-challenge 1122334455667788
```

A fixed, known challenge lets captured Net-NTLMv2 responses be cracked against
precomputed tables, and is the convention assumed by some downstream cracking
setups. Use a random challenge (the default) unless you specifically need a
deterministic one.

### IP whitelist (repeatable)

```
--allow-ip 10.0.0.0/8
--allow-ip 192.168.1.50
```

Accepts a CIDR or a bare IP (host route). **If any `--allow-ip` is set, every
connection from an address outside the whitelist is dropped at connect time**
and logged as `[!] rejected connection from ...`. With no rules, all sources
are accepted.

### Diagnostics

Logging uses [`golog`](https://github.com/jfjallid/golog), shared across the
adtools suite. The `--debug` / `--verbose` flags accept an optional
comma-separated package-name-suffix filter:

| Flag                   | Description |
|------------------------|-------------|
| `--debug`              | Bare form: debug logging for **every** registered package |
| `--debug=smb,server`   | `=` form: debug only the listed package-name suffixes |
| `--verbose`            | Info-level logging; same filter syntax as `--debug` |
| `--list-log-packages`  | Print the targetable package names and exit |

`--debug` and `--verbose` may be combined with different filters; a package
targeted by both ends up at the higher (debug) level. Passing **both** bare
(all packages at two levels at once) is ambiguous and rejected — be specific,
e.g. `--debug=smb,server --verbose=main`.

## Share enumeration

The server exposes the reserved `IPC$` pipe and implements the `srvsvc`
endpoint, so clients (e.g. `smbclient -L`, `net view`) can list the configured
shares over MS-SRVS.

## Examples

Capture-only honeypot on a high port (no root needed), logging hashes to a file:

```sh
smbserver --bind :4445 --dump-creds --cred-log /tmp/creds.hashcat
```

A writable drop share for one user plus a throwaway memory share, restricted to
the lab subnet:

```sh
smbserver \
  --account user=alice,password=Summer2026! \
  --share name=Drop,backend=disk,path=/srv/drop,writable_users=alice \
  --share name=Scratch,backend=memory \
  --allow-ip 10.10.0.0/16
```

Everything from a config file, then override just the listen address and force
encryption for this run:

```sh
smbserver --config server.yaml --bind 0.0.0.0:445 --require-encryption
```

## Shutdown

`SIGINT` / `SIGTERM` trigger a graceful shutdown with a 5-second timeout.

## Notes & caveats

- Authentication is NTLM only; there is no Kerberos server side.
- Binding to the default port `445` requires elevated privileges. On Linux a
  conflicting host SMB service (e.g. Samba) must be stopped first, or use a
  different `--bind` port.
- `IPC$` is reserved and cannot be used as a share name.
