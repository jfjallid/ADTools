# ADTools

## Description
ADTools is a collection of small tools I've created to aid in security
assessments of Active Directory. Most of the tools rely on the library [go-smb](https://github.com/jfjallid/go-smb)
and only includes a small client to parse cli arguments and call the library.

## Building the tools
Use the Makefile to build all the tools as static binaries and place them in the
bin/ folder:
```bash
make
```

## Installation
Copy the compiled binaries to the ${HOME}/.local/bin/ directory
```bash
./install
```

## Usage

### WMIExec
```
Usage: ./wmiexec [options]

options:
      --host <target>          Hostname or ip address of remote server. Must be hostname when using Kerberos
  -P, --port <int>             SMB Port (default 445)
  -d, --domain <name/fqdn>     Domain name to use for login
  -u, --user <string>          Username
  -p, --pass <string>          Password
  -n, --no-pass                Disable password prompt and send no credentials
      --hash <NT Hash>         Hex encoded NT Hash for user password
      --local                  Authenticate as a local user instead of domain user
      --null                   Attempt null session authentication
  -k, --kerberos               Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
      --dc-ip <ip>             Optionally specify ip of KDC when using Kerberos authentication
      --target-ip <ip>         Optionally specify ip of target when using Kerberos authentication
      --dns-host <ip:port>     Override system's default DNS resolver
      --dns-tcp                Force DNS lookups over TCP. Default true when using --socks-host
      --aes-key <hex>          Use a hex encoded AES128/256 key for Kerberos authentication
  -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
  -c, --command <str>          Command to execute
      --workdir <str>          Working directory for command
      --socks-host <target>    Establish connection via a SOCKS5 proxy server
      --socks-port <port>      SOCKS5 proxy port (default 1080)
      --noenc                  Disable RPC encryption
      --debug                  Enable debug logging
      --verbose                Enable verbose logging
  -v, --version                Show version
```

### WMIQuery
```
Usage: ./wmiquery [options]

options:
      --host <target>          Hostname or ip address of remote server. Must be hostname when using Kerberos
  -P, --port <int>             SMB Port (default 445)
  -d, --domain <name/fqdn>     Domain name to use for login
  -u, --user <string>          Username
  -p, --pass <string>          Password
  -n, --no-pass                Disable password prompt and send no credentials
      --hash <NT Hash>         Hex encoded NT Hash for user password
      --local                  Authenticate as a local user instead of domain user
      --null                   Attempt null session authentication
  -k, --kerberos               Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
      --dc-ip <ip>             Optionally specify ip of KDC when using Kerberos authentication
      --target-ip <ip>         Optionally specify ip of target when using Kerberos authentication
      --dns-host <ip:port>     Override system's default DNS resolver
      --dns-tcp                Force DNS lookups over TCP. Default true when using --socks-host
      --aes-key <hex>          Use a hex encoded AES128/256 key for Kerberos authentication
  -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
  -q, --query <str>            WQL query string
      --namespace <str>        WMI namespace (default //./root/cimv2)
      --socks-host <target>    Establish connection via a SOCKS5 proxy server
      --socks-port <port>      SOCKS5 proxy port (default 1080)
      --noenc                  Disable RPC encryption
      --debug                  Enable debug logging
      --verbose                Enable verbose logging
  -v, --version                Show version
```

### DCOMExec
```
Usage: ./dcomexec [options]

options:
      --host <target>          Hostname or ip address of remote server.
  -P, --port <int>             SMB Port (default 445)
  -d, --domain <name/fqdn>     Domain name to use for login
  -u, --user <string>          Username
  -p, --pass <string>          Password
  -n, --no-pass                Disable password prompt and send no credentials
      --hash <NT Hash>         Hex encoded NT Hash for user password
      --local                  Authenticate as a local user instead of domain user
      --null                   Attempt null session authentication
      --dns-host <ip:port>     Override system's default DNS resolver
      --dns-tcp                Force DNS lookups over TCP. Default true when using --socks-host
  -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
  -c, --command <str>          Command to execute (MMC mode) or shell command (generic COM mode)
      --args <str>             Parameters passed to the command (MMC mode)
      --workdir <str>          Working directory for command
      --clsid <guid>           COM class GUID to activate (generic COM mode)
      --iid <guid>             Interface GUID to request (default: IID_IDispatch)
      --dispatch-name <str>    IDispatch method/property name (supports dot-chains, e.g. A.B.C)
      --dispatch-args <str>    Comma-separated typed arguments (prefix: s:string, i:int, b:bool; default: string)
      --opnum <int>            Raw opnum for non-IDispatch calls (reads hex stub data from stdin)
      --property-get           Use DISPATCH_PROPERTYGET instead of DISPATCH_METHOD
      --property-put           Use DISPATCH_PROPERTYPUT instead of DISPATCH_METHOD
      --quit                   Call Quit on the root object after execution (terminates server process, e.g. mmc.exe)
      --socks-host <target>    Establish connection via a SOCKS5 proxy server
      --socks-port <port>      SOCKS5 proxy port (default 1080)
      --noenc                  Disable RPC encryption
      --debug                  Enable debug logging
      --verbose                Enable verbose logging
  -v, --version                Show version
```

### ATExec
```
Usage: ./atexec [options]

options:
      --host <target>          Hostname or ip address of remote server. Must be hostname when using Kerberos
  -P, --port <int>             SMB Port (default 445)
  -d, --domain <name/fqdn>     Domain name to use for login
  -u, --user <string>          Username
  -p, --pass <string>          Password
  -n, --no-pass                Disable password prompt and send no credentials
      --hash <NT Hash>         Hex encoded NT Hash for user password
      --local                  Authenticate as a local user instead of domain user
  -k, --kerberos               Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
      --dc-ip <ip>             Optionally specify ip of KDC when using Kerberos authentication
      --target-ip <ip>         Optionally specify ip of target when using Kerberos authentication
      --dns-host <ip:port>     Override system's default DNS resolver
      --dns-tcp                Force DNS lookups over TCP. Default true when using --socks-host
      --aes-key <hex>          Use a hex encoded AES128/256 key for Kerberos authentication
  -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
      --relay                  Start an SMB listener that will relay incoming
                               NTLM authentications to the remote server and
                               use that connection. NOTE that this forces SMB 2.1
                               without encryption.
      --relay-port <port>      Listening port for relay (default 445)
  -c, --command <str>          Command to execute
  -a, --args <str>             Command arguments
      --no-delete              Do not delete the scheduled task after execution
      --socks-host <target>    Establish connection via a SOCKS5 proxy server
      --socks-port <port>      SOCKS5 proxy port (default 1080)
      --noenc                  Disable smb encryption
      --smb2                   Force smb 2.1
      --debug                  Enable debug logging
      --verbose                Enable verbose logging
  -v, --version                Show version
```

### DCSync
```
Usage: ./dcsync [options]

options:
      --host <target>          Hostname or ip address of remote DC. Must be hostname when using Kerberos
  -P, --port <int>             EPM Port (default 135)
  -d, --domain <name/fqdn>     Domain name to use for login
  -u, --user <string>          Username
  -p, --pass <string>          Password
  -n, --no-pass                Disable password prompt and send no credentials
      --hash <NT Hash>         Hex encoded NT Hash for user password
  -k, --kerberos               Use Kerberos authentication. (KRB5CCNAME will be checked on Linux)
      --dc-ip <ip>             Optionally specify ip of KDC when using Kerberos authentication
      --target-ip <ip>         Optionally specify ip of target when using Kerberos authentication
      --dns-host <ip:port>     Override system's default DNS resolver
      --dns-tcp                Force DNS lookups over TCP. Default true when using --socks-host
      --aes-key <hex>          Use a hex encoded AES128/256 key for Kerberos authentication
  -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
      --target <DOMAIN\User>   Single target account to DCSync
      --target-file <path>     Read target accounts from file, one account per line
      --ldap-filter            LDAP filter string to select which accounts to target
      --exclude-users          Comma-separated list of users to skip when targeting all accounts
      --enabled                Filter on enabled accounts when using ldap
      --use-samr               Enumerate usernames via MS-SAMR instead of LDAP
      --history                Include NT/LM/WDigest hash history
      --ntlm-only              Only sync NTLM hashes.
      --socks-host <target>    Establish connection via a SOCKS5 proxy server
      --socks-port <port>      SOCKS5 proxy port (default 1080)
      --noenc                  Run ldap queries without encryption.
      --tls                    Run ldap over TLS port 636
      --starttls               Try to upgrade ldap to TLS on port 389
      --format                 Output format (impacket,default,...)
      --debug                  Enable debug logging
      --verbose                Enable verbose logging
  -v, --version                Show version
```

### LdapTool
```
Usage: ldaptool <subcommand> [options]

Subcommands:
  create-computer        Create a new computer account
  create-user            Create a new user account
  delete-object          Delete an LDAP object by DN
  detect-channel-binding Detect if LDAP channel binding is required
  detect-signing         Detect if LDAP signing is required
  group                  Add or remove group members
  laps                   Read LAPS local-admin passwords
  modify                 Modify attributes on an LDAP object
  rbcd                   Manage msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
  search                 Search for LDAP objects
  shadow-credentials     Manage msDS-KeyCredentialLink (Shadow Credentials)
  shell                  Launch interactive shell
  spn                    Manage servicePrincipalName on an object

Run 'ldaptool <subcommand> --help' for action-specific options.

    Connection options:
          --host                 DC hostname or IP (required)
      -P, --port                 LDAP port (default 389, or 636 with --tls)
          --tls                  Use LDAPS (implicit TLS)
          --starttls             Use StartTLS on plain LDAP port
          --insecure             Skip TLS certificate verification
          --base-dn              Search base DN (auto-detected if omitted)
          --naming-context       Naming context: default, configuration, schema, root
          --sasl                 SASL security: none, sign, seal
          --channel              Enable TLS channel binding
      -t, --timeout              Dial timeout (e.g. 5s, 1m; default 5s)
          --socks-host           SOCKS5 proxy host
          --socks-port           SOCKS5 proxy port (default 1080)

    Authentication (NTLM unless --simple/--anonymous/--kerberos):
      -d, --domain               AD domain (e.g. CORP)
      -u, --user                 Username (or full DN with --simple)
      -p, --pass                 Password (or set AD_PASSWORD env var)
          --hash                 NT hash (pass-the-hash / Kerberos RC4)
      -n, --no-pass              Send no password (unauthenticated NTLM bind)
          --simple               LDAP simple bind (DN/password)
          --anonymous            LDAP simple anonymous bind (no creds)

    Kerberos (with -k/--kerberos):
      -k, --kerberos             Use Kerberos (GSSAPI) instead of NTLM
          --ccache               Path to Kerberos credential cache file (falls back to $KRB5CCNAME)
          --krb5conf             Path to krb5.conf (default: /etc/krb5.conf)
          --realm                Kerberos realm (defaults to upper-cased --domain)
          --aes-key              Hex AES128/256 key
          --override-spn         Service principal name (default: ldap/<host>)
          --dc-ip <ip[:port]>    KDC address override (default port 88)
          --dns-host <ip[:port]> Override system's default DNS resolver (default port 53)
          --dns-tcp              Force DNS lookups over TCP

```
