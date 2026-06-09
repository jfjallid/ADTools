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
      --keytab-file <file>     Authenticate using keys from a keytab file (implies -k). User and
                               domain are taken from the first keytab entry if not specified
  -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
  -c, --command <str>          Command to execute
      --workdir <str>          Working directory for command
      --socks-host <target>    Establish connection via a SOCKS5 proxy server
      --socks-port <port>      SOCKS5 proxy port (default 1080)
      --noenc                  Disable RPC encryption
      --debug                  Enable debug logging. Bare --debug enables every registered
                               package; --debug=smb,dcerpc filters to the listed package-name
                               suffixes (the '=' form is required for the filter).
      --verbose                Enable verbose logging (same --verbose=pkg filter syntax)
      --list-log-packages      List registered log package names targetable by
                               --debug=<suffix> or --verbose=<suffix>, then exit
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
      --keytab-file <file>     Authenticate using keys from a keytab file (implies -k). User and
                               domain are taken from the first keytab entry if not specified
  -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
  -q, --query <str>            WQL query string
      --namespace <str>        WMI namespace (default //./root/cimv2)
      --socks-host <target>    Establish connection via a SOCKS5 proxy server
      --socks-port <port>      SOCKS5 proxy port (default 1080)
      --noenc                  Disable RPC encryption
      --debug                  Enable debug logging. Bare --debug enables every registered
                               package; --debug=smb,dcerpc filters to the listed package-name
                               suffixes (the '=' form is required for the filter).
      --verbose                Enable verbose logging (same --verbose=pkg filter syntax)
      --list-log-packages      List registered log package names targetable by
                               --debug=<suffix> or --verbose=<suffix>, then exit
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
      --debug                  Enable debug logging. Bare --debug enables every registered
                               package; --debug=smb,dcerpc filters to the listed package-name
                               suffixes (the '=' form is required for the filter).
      --verbose                Enable verbose logging (same --verbose=pkg filter syntax)
      --list-log-packages      List registered log package names targetable by
                               --debug=<suffix> or --verbose=<suffix>, then exit
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
      --keytab-file <file>     Authenticate using keys from a keytab file (implies -k). User and
                               domain are taken from the first keytab entry if not specified
  -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
  -c, --command <str>          Command to execute
  -a, --args <str>             Command arguments
      --no-delete              Do not delete the scheduled task after execution
      --socks-host <target>    Establish connection via a SOCKS5 proxy server
      --socks-port <port>      SOCKS5 proxy port (default 1080)
      --noenc                  Disable smb encryption (does not work for WinServ 2025)
      --smb2                   Force smb 2.1
      --debug                  Enable debug logging. Bare --debug enables every registered
                               package; --debug=smb,dcerpc filters to the listed package-name
                               suffixes (the '=' form is required for the filter).
      --verbose                Enable verbose logging (same --verbose=pkg filter syntax)
      --list-log-packages      List registered log package names targetable by
                               --debug=<suffix> or --verbose=<suffix>, then exit
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
      --keytab-file <file>     Authenticate using keys from a keytab file (implies -k). User and
                               domain are taken from the first keytab entry if not specified
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
      --debug                  Enable debug logging. Bare --debug enables every registered
                               package; --debug=smb,dcerpc filters to the listed package-name
                               suffixes (the '=' form is required for the filter).
      --verbose                Enable verbose logging (same --verbose=pkg filter syntax)
      --list-log-packages      List registered log package names targetable by
                               --debug=<suffix> or --verbose=<suffix>, then exit
  -v, --version                Show version
```

### LdapTool
```
Usage: ldaptool <subcommand> [options]

Subcommands:
  access                 Compute a principal's effective access to an object
  create-computer        Create a new computer account
  create-user            Create a new user account
  dacl                   View and modify DACLs on object security descriptors
  delete-object          Delete an LDAP object by DN
  detect-channel-binding Detect if LDAP channel binding is required
  detect-signing         Detect if LDAP signing is required
  group                  Add or remove group members
  laps                   Read LAPS local-admin passwords
  modify                 Modify attributes on an LDAP object
  owner                  View and change the owner SID of an object's security descriptor
  rbcd                   Manage msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
  search                 Search for LDAP objects
  set-password           Set or change an account's password (unicodePwd)
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
      -p, --pass                 Password (bare -p prompts on terminal)
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
          --keytab-file <file>   Authenticate with a Kerberos keytab (implies -k;
                                 principal and realm default to the keytab's first
                                 entry, overridable with --user and --realm/--domain)
          --override-spn         Service principal name (default: ldap/<host>)
          --dc-ip <ip[:port]>    KDC address override for Kerberos (default port 88)
          --target-ip <ip>       IP to connect to for LDAP; skips DNS of --host
          --dns-host <ip[:port]> Override system's default DNS resolver (default port 53)
          --dns-tcp              Force DNS lookups over TCP

    Diagnostics:
          --debug                Enable debug logging. Bare --debug turns on every registered
                                 package; --debug=ldap,smb turns on only the listed package-name
                                 suffixes (the '=' form is required for the filter).
          --verbose              Enable verbose output. Same filter syntax as --debug. --debug
                                 and --verbose may be combined with different filters; a package
                                 targeted by both gets the higher level.
          --list-log-packages    List the registered log package names that can be targeted with
                                 --debug=<suffix> or --verbose=<suffix>, then exit

```

### RPCTrigger
Authentication coercion. Forces the target to authenticate to a listener via
`ElfrOpenBELW` (MS-EVEN) or `RpcRemoteFindFirstPrinterChangeNotificationEx`
(MS-RPRN).
```
Usage: ./rpctrigger [options]

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
          --keytab-file <file>     Authenticate with a Kerberos keytab (implies -k; principal and realm are read from the keytab when --user/--domain are omitted)
      -t, --timeout <duration>     Dial timeout specified in 5s, 1m, 10m format (default 5s)
          --method <even|rprn>     Coercion method: "even" (ElfrOpenBELW) or "rprn" (RpcRemoteFindFirstPrinterChangeNotificationEx)
          --listener <unc>         Trigger destination. UNC backup file path for "even", listener UNC (e.g. \\10.0.0.1) for "rprn"
          --socks-host <target>    Establish connection via a SOCKS5 proxy server
          --socks-port <port>      SOCKS5 proxy port (default 1080)
          --noenc                  Disable smb encryption
          --smb2                   Force smb 2.1
          --debug                  Enable debug logging. Bare --debug turns on every
                                   registered package; --debug=smb,dcerpc turns on only the
                                   listed package-name suffixes (the '=' form is required
                                   for the filter).
          --verbose                Enable verbose logging. Same filter syntax as --debug.
                                   --debug and --verbose may be combined with different
                                   filters; a package targeted by both gets the higher level.
          --list-log-packages      List the registered log package names that can be
                                   targeted with --debug=<suffix> or --verbose=<suffix>,
                                   then exit
      -v, --version                Show version
```

### GPOParser
Understand what Active Directory GPOs *do* (GptTmpl.inf security settings, GPP
Groups/Registry/Tasks/Services, Registry.pol, scripts) and *where* they apply
(gPLink + OU inheritance → affected computers). Reads SYSVOL over SMB and queries
AD over LDAP.

This tool is mostly a port of https://github.com/Group3r/Group3r to Go to support
running it from Linux, but it also includes a few features from https://github.com/synacktiv/gpoParser.
So credit goes to them for all their hard work creating those tools.
```
Usage: gpoparser <subcommand> [options]

Subcommands:
  assess     Flag exploitable GPO misconfigurations (privileges, groups, registry, creds)
  display    Show what GPOs change (groups, privileges, registry, scripts...)
  enrich     Emit SharpHound-native JSON for BloodHound CE upload
  local      Parse GPOs offline from a local SYSVOL copy + LDAP dump
  query      Map GPOs to affected computers (and vice versa)
  remote     Enumerate and parse GPOs live over LDAP + SYSVOL

Run 'gpoparser <subcommand> --help' for mode-specific options.

    Connection options (remote mode):
          --host                 DC hostname or IP (required; hostname for Kerberos)
      -P, --port                 LDAP port (default 389, or 636 with --tls)
          --tls                  Use LDAPS (implicit TLS)
          --starttls             Use StartTLS on plain LDAP port
          --insecure             Skip TLS certificate verification
          --base-dn              Search base DN (auto-detected if omitted)
          --sasl                 SASL security: none, sign, seal
          --channel              Enable TLS channel binding
          --smb-port             SMB port for SYSVOL (default 445)
          --noenc                Disable SMB encryption when reading SYSVOL
      -t, --timeout              Dial timeout (e.g. 5s, 1m; default 5s)
          --socks-host           SOCKS5 proxy host
          --socks-port           SOCKS5 proxy port (default 1080)

    Authentication (NTLM unless --simple/--anonymous/--kerberos):
      -d, --domain               AD domain (e.g. CORP)
      -u, --user                 Username (or full DN with --simple)
      -p, --pass                 Password (bare -p prompts on terminal)
          --hash                 NT hash (pass-the-hash / Kerberos RC4)
      -n, --no-pass              Send no password (unauthenticated bind)
          --simple               LDAP simple bind (DN/password)
          --anonymous            LDAP simple anonymous bind (no creds)

    Kerberos (with -k/--kerberos):
      -k, --kerberos             Use Kerberos (GSSAPI) instead of NTLM
          --keytab-file <file>   Authenticate with a Kerberos keytab (implies -k; principal and
                                 realm are read from the keytab when --user/--domain are omitted)
          --ccache               Kerberos credential cache file (falls back to $KRB5CCNAME)
          --krb5conf             Path to krb5.conf (default: /etc/krb5.conf)
          --realm                Kerberos realm (defaults to upper-cased --domain)
          --aes-key              Hex AES128/256 key
          --override-spn         LDAP service principal name (default: ldap/<host>)
          --dc-ip <ip[:port]>    KDC address override (default port 88)
          --target-ip <ip>       IP to connect to; skips DNS of --host
          --dns-host <ip[:port]> Override system's default DNS resolver (default port 53)
          --dns-tcp              Force DNS lookups over TCP

    Diagnostics:
          --debug                Enable debug logging. Bare --debug turns on every registered
                                 package; --debug=smb,ldap turns on only the listed package-name
                                 suffixes (the '=' form is required for the filter).
          --verbose              Enable verbose logging. Same filter syntax as --debug. --debug
                                 and --verbose may be combined with different filters; a package
                                 targeted by both gets the higher level.
          --list-log-packages    List the registered log package names that can be targeted with
                                 --debug=<suffix> or --verbose=<suffix>, then exit
```

### SMBServer
A standalone SMB server: serve disk/memory shares, capture incoming NTLM
authentications (Net-NTLMv2, hashcat format), and act as a drop/landing point
for coercion. Configurable via CLI flags or a YAML file.
```
Usage: ./smbserver [options]

    options:
          --config <path>         YAML config file (CLI flags override any field)
      -b, --bind <addr>           Listen address (default :445)

      SMB protocol:
          --min-dialect <ver>     2.0.2 | 2.1 | 3.0 | 3.0.2 | 3.1.1 (default 2.0.2)
          --max-dialect <ver>     ... (default 3.1.1)
          --no-encryption         Disable SMB 3.x encryption capability (default: advertised)
          --require-encryption    Force every session into encrypted mode (only applies to smb 3.1.1)
          --require-signing       Advertise signing required
          --netbios-name <name>   Advertised NetBIOS server name (default GO-SMB)
          --netbios-domain <name> Advertised NetBIOS domain (default WORKGROUP)
          --dns-name <fqdn>       Advertised DNS computer name
          --dns-domain <name>     Advertised DNS domain name
          --ntlm-challenge <hex>  Hardcode the server's ntlm challenge

      Sessions:
          --allow-guest           Permit guest sessions on auth failure
          --allow-anonymous       Permit null sessions

      Shares (repeatable):
          --share <spec>          name=Public,backend=disk,path=/srv/pub,readonly=true,encrypt=false
                                  or name=Drop,backend=memory

      Accounts (repeatable):
          --account <spec>        user=alice,domain=WORKGROUP,password=secret
                                  or user=alice,nthash=<32-hex>

      Credential dumping:
          --dump-creds            Log every captured NTLM AUTH (Net-NTLMv2 hashcat)
          --cred-log <path>       Append hashcat lines to file (mode 0600)

      IP whitelist (repeatable):
          --allow-ip <cidr>       Whitelist CIDR or IP. If any --allow-ip is set,
                                  others are silently dropped via OnConnect.

      Diagnostics:
          --debug                 Debug logging. Bare --debug turns on every registered
                                  package; --debug=smb,server turns on only the listed
                                  package-name suffixes (the '=' form is required for the filter).
          --verbose               Verbose logging (info). Same filter syntax as --debug.
                                  --debug and --verbose may be combined with different filters;
                                  a package targeted by both gets the higher level.
          --list-log-packages     List the registered log package names that can be targeted
                                  with --debug=<suffix> or --verbose=<suffix>, then exit
      -v, --version               Show version
```
