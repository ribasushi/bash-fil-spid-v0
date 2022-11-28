#!/bin/bash

FIL_AUTHHDR="FIL-SPID-V0"

# we will be briefly interacting with a pretty sensitive secret: just be thorough
BIN_cat="/bin/cat"
BIN_curl="/usr/bin/curl"
BIN_jq="/usr/bin/jq"
BIN_grep="/bin/grep"
BIN_head="/usr/bin/head"
BIN_b64="/usr/bin/base64"

#
# Filecoin StorageProvider ID ( fil-spid.bash )
#
# A simple system for stateless StorageProvider authentication, using a custom
# `Authorization: FIL-SPID...` HTTP header.
#
# Typical usage:
#   curl -sLH "Authorization: $( ./fil-spid.bash f0xxxxx )" ...
#
# The exaustive list of tasks performed by this short program is:
# - Read up to 2048 bytes of STDIN if available
# - Determine daemon Host+Port+ApiToken
# - Determine current_fil_epoch: ( $now_unix - $fil_genesis_unix ) / 30
# - Get chain tipset at finality ( $current_fil_epoch - 900 )
# - Determine the supplied storage-provider's Worker address in the finalized state ( $current_fil_epoch - 900 )
# - Get the drand signature for $current_fil_epoch
# - Sign the binary string "\x20\x20\x20{96byte-drand-Signature}{optional-up-to-2k-read-from-STDIN}" using the determined worker key
# - Compose and print the string "${FIL_AUTHHDR} ${current_fil_epoch};f0xxxxx;${hex_encoded_worker_key_signature};${optional-hex-encoded-up-to-2k-read-from-STDIN}"
#
# ( help turning this into a proper spec most welcome )
#

set -eu
set -o pipefail

die() { echo "$@" 1>&2 ; exit 1 ; }

[[ "$#" == "1" ]] || die "StorageProviderID ( f0xxxx ) as sole argument required, $# arguments provided"
[[ "$1" =~ ^f0[0-9]+$ ]] || die "Expecting StorageProviderID ( f0xxxx ) as sole argument, got '$1'"

FIL_SP="$1"

# slurp up to 2k of input if nonterminal
B64_OPTIONAL_PAYLOAD=""
if [[ ! -t 0 ]]; then
  B64_OPTIONAL_PAYLOAD="$( "$BIN_head" -c 2048 | "$BIN_b64" -w 0 )"
fi
if [[ "${#B64_OPTIONAL_PAYLOAD}" != 0 ]]; then
  printf "optional input from STDIN encoded as %d base64 bytes\n" ${#B64_OPTIONAL_PAYLOAD} 1>&2
fi


# derive API_INFO from implied defaults if necessary
LOTUS_PATH="${LOTUS_PATH:-$HOME/.lotus}"
LOTUS_CFG_MADDR="$( "$BIN_cat" "$LOTUS_PATH/api" 2>/dev/null | "$BIN_grep" -vE '/ip4/0.0.0.0/|/ip6/::/' || true )"
FULLNODE_API_INFO="${FULLNODE_API_INFO:-$( "$BIN_cat" "$LOTUS_PATH/token" || true ):${LOTUS_CFG_MADDR:-/ip4/127.0.0.1/tcp/1234/http}}"

# derive token + maddr, then host/port
IFS=':' read -r API_TOKEN API_MADDR <<<"$FULLNODE_API_INFO"
IFS='/' read -r IGNORE API_NPROTO API_HOST API_TPROTO API_PORT API_APROTO <<<"$API_MADDR"

if [[ "$API_NPROTO" == "ip6" ]]; then
  API_HOST="\[$API_HOST\]"
fi

lotus_apicall() {
  local input="$( "$BIN_cat" )"
  local output="$( "$BIN_curl" -m5 -s http://$API_HOST:$API_PORT/rpc/v0 -XPOST -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' --data "$input" )"
  local maybe_err="$( $BIN_jq -rc '.error // empty' <<<"$output" )"
  [[ -z "$maybe_err" ]] && [[ -n "$output" ]] || die -e "Error executing '$input' against API http://$API_HOST:$API_PORT\n${maybe_err:-no result from API call}"
  echo "$output"
}

B64_SPACEPAD="ICAg"  # use this to pefix the random beacon, lest it becomes valid CBOR
FIL_GENESIS_UNIX="1598306400"
FIL_CURRENT_EPOCH="$(( ( $( printf "%(%s)T" -1 ) - $FIL_GENESIS_UNIX ) / 30  ))"
FIL_FINALIZED_TIPSET="$(
  printf '{ "jsonrpc": "2.0", "id":1, "method": "Filecoin.ChainGetTipSetByHeight", "params": [ %d, null ] }' "$(( "$FIL_CURRENT_EPOCH" - 900 ))" \
    | lotus_apicall | "$BIN_jq" -rc .result.Cids
)"
FIL_FINALIZED_WORKER_ID="$(
  printf '{ "jsonrpc": "2.0", "id":1, "method": "Filecoin.StateMinerInfo", "params": [ "%s", %s ] }' "$FIL_SP" "$FIL_FINALIZED_TIPSET" \
    | lotus_apicall | "$BIN_jq" -rc .result.Worker
)"
FIL_CURRENT_DRAND_B64="$(
  printf '{ "jsonrpc": "2.0", "id":1, "method": "Filecoin.BeaconGetEntry", "params": [ %d ] }' "$FIL_CURRENT_EPOCH" \
    | lotus_apicall | "$BIN_jq" -rc .result.Data
)"
# the plain append of ${B64_OPTIONAL_PAYLOAD} works because ${FIL_CURRENT_DRAND_B64} is always 96 bytes encoded to 128 chars WITHOUT padding
FIL_AUTHSIG="$(
  printf '{ "jsonrpc": "2.0", "id":1, "method": "Filecoin.WalletSign", "params": [ "%s", "%s" ] }' "$FIL_FINALIZED_WORKER_ID" "${B64_SPACEPAD}${FIL_CURRENT_DRAND_B64}${B64_OPTIONAL_PAYLOAD}" \
    | lotus_apicall | "$BIN_jq" -rc '.result.Data'
)"

hdr="$(printf '%s %d;%s;%s' "$FIL_AUTHHDR" "$FIL_CURRENT_EPOCH" "$FIL_SP" "$FIL_AUTHSIG")"
if [[ "${#B64_OPTIONAL_PAYLOAD}" != 0 ]]; then
  hdr="$hdr;$B64_OPTIONAL_PAYLOAD"
fi
echo "$hdr"
