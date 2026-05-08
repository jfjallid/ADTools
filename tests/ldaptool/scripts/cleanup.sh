#!/usr/bin/env bash
#
# Orphan sweep for lt_* test objects. Run after a test panic or as a CI
# safety net. Reads the same LDAPTOOL_* env vars as the test suite.
#
# Strategy: search for objects whose sAMAccountName starts with lt_
# (the test suite's prefix; short to fit AD's 20-char sAMAccountName cap).
# Parse the DNs, delete each via the delete-object subcommand. Idempotent.
#
# Honors LDAPTOOL_DRY_RUN=1 to print what would be deleted without acting.

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LDAPTOOL_BIN="${LDAPTOOL_BIN:-$REPO_ROOT/bin/ldaptool}"

if [[ ! -x "$LDAPTOOL_BIN" ]]; then
  echo "error: ldaptool binary not found at $LDAPTOOL_BIN" >&2
  echo "build with 'make' from the repo root or set LDAPTOOL_BIN" >&2
  exit 2
fi

for v in LDAPTOOL_HOST LDAPTOOL_USER LDAPTOOL_PASS LDAPTOOL_DOMAIN; do
  if [[ -z "${!v:-}" ]]; then
    echo "error: $v is not set" >&2
    exit 2
  fi
done

common_args=(
  --host "$LDAPTOOL_HOST"
  --user "$LDAPTOOL_USER"
  --pass "$LDAPTOOL_PASS"
  --domain "$LDAPTOOL_DOMAIN"
)
[[ -n "${LDAPTOOL_DC_IP:-}" ]] && common_args+=(--dc-ip "$LDAPTOOL_DC_IP")
[[ -n "${LDAPTOOL_DNS_HOST:-}" ]] && common_args+=(--dns-host "$LDAPTOOL_DNS_HOST")

# 1) Enumerate ldaptest_* objects (users + computers share sAMAccountName).
# The "$" suffix on machine accounts is included in the search anchor; the
# wildcard catches both bare and $-suffixed forms.
search_out="$("$LDAPTOOL_BIN" search "${common_args[@]}" \
  --filter "(sAMAccountName=lt_*)" \
  --attrs distinguishedName \
  --no-banner 2>&1)"

# Parse "DN: <dn>" lines (human format).
mapfile -t dns < <(printf '%s\n' "$search_out" | sed -n 's/^DN:[[:space:]]*//p')

if [[ ${#dns[@]} -eq 0 ]]; then
  echo "[*] no lt_* orphans found"
  exit 0
fi

echo "[*] found ${#dns[@]} lt_* orphan(s)"
for dn in "${dns[@]}"; do
  if [[ "${LDAPTOOL_DRY_RUN:-0}" == "1" ]]; then
    echo "  [dry-run] would delete: $dn"
    continue
  fi
  echo "  deleting: $dn"
  "$LDAPTOOL_BIN" delete-object "${common_args[@]}" --dn "$dn" >/dev/null 2>&1 || \
    echo "    [warn] delete failed for $dn" >&2
done

echo "[*] cleanup complete"
