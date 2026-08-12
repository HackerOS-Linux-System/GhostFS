#!/usr/bin/env bash
# ghostfs-admin.sh — GhostFS administration helper (cybersec build)
# Cybersec mode is the only mode — encryption is always on.
#
# Usage: ghostfs-admin.sh <command> [options]
# Commands:
#   keygen   <outfile>                              — generate 256-bit master key
#   format   <device> [--passphrase]               — format new volume
#   mount    <device> <mountpoint> <keyfile|--passphrase> [rate_mb]
#   umount   <mountpoint>                           — unmount
#   audit    <device> [n=50]                        — show last n audit entries
#   quota    <device> <uid> [limit_mb]              — show or set quota
#   forensics-verify <device>                       — verify forensics chain
#   forensics-tail   <device> [n=100]               — show last n entries
#   ids      <device> [n=50]                        — show IDS alerts
#   mac-label   <device> <ino> <level> [comps_hex]  — set MAC label
#   mac-clear   <device> <uid> <level> [comps_hex] [--trusted]

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

info() { echo -e "${CYAN}[INFO]${RESET} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
die()  { echo -e "${RED}[ERR ]${RESET} $*" >&2; exit 1; }

GHOSTFS="${GHOSTFS_BIN:-ghostfs}"
command -v "$GHOSTFS" &>/dev/null || die "ghostfs binary not found. Set GHOSTFS_BIN or install to PATH."

cmd="${1:-help}"; shift || true

case "$cmd" in

keygen)
    out="${1:?output file required}"; shift
    [[ -e "$out" ]] && die "$out already exists — refusing to overwrite"
    "$GHOSTFS" keygen --output "$out"
    ok "Key written to $out"
    warn "Keep this file safe. Losing it = losing all data."
    ;;

format)
    dev="${1:?device required}"; shift
    if [[ "${1:-}" == "--passphrase" ]]; then
        info "Formatting $dev with Argon2id passphrase KDF..."
        "$GHOSTFS" mkfs --device "$dev"
    else
        key="${1:?key file or --passphrase required}"; shift
        [[ -r "$key" ]] || die "Key file $key not readable"
        info "Formatting $dev with key file $key..."
        "$GHOSTFS" mkfs --device "$dev" --key-out /dev/null
    fi
    ok "Formatted $dev"
    ;;

mount)
    dev="${1:?device required}"; shift
    mnt="${1:?mountpoint required}"; shift
    auth="${1:?key file or --passphrase required}"; shift
    rate="${1:-100}"; shift || true
    mkdir -p "$mnt"
    if [[ "$auth" == "--passphrase" ]]; then
        info "Mounting $dev → $mnt (passphrase, rate=${rate}MiB/s)"
        "$GHOSTFS" mount --device "$dev" --mountpoint "$mnt" \
            --compression zstd --noatime --rate-limit-mb "$rate" &
    else
        [[ -r "$auth" ]] || die "Key file $auth not readable"
        info "Mounting $dev → $mnt (key-file, rate=${rate}MiB/s)"
        "$GHOSTFS" mount --device "$dev" --mountpoint "$mnt" \
            --key-file "$auth" --compression zstd --noatime \
            --rate-limit-mb "$rate" &
    fi
    sleep 1
    mount | grep -q ghostfs && ok "Mounted at $mnt" || die "Mount failed"
    ;;

umount)
    mnt="${1:?mountpoint required}"; shift
    info "Unmounting $mnt (keys will be zeroed from memory)..."
    "$GHOSTFS" umount --mountpoint "$mnt"
    ok "Unmounted $mnt"
    ;;

audit)
    dev="${1:?device required}"; shift
    n="${1:-50}"; shift || true
    info "Last $n audit entries from $dev"
    "$GHOSTFS" audit --device "$dev" tail --count "$n"
    ;;

quota)
    dev="${1:?device required}"; shift
    uid="${1:?uid required}"; shift
    limit_mb="${1:-}"; shift || true
    if [[ -n "$limit_mb" ]]; then
        limit_bytes=$(( limit_mb * 1048576 ))
        info "Setting quota for uid $uid to ${limit_mb} MiB"
        "$GHOSTFS" quota --device "$dev" set --uid "$uid" --limit "$limit_bytes"
        ok "Quota set"
    else
        "$GHOSTFS" quota --device "$dev" show --uid "$uid"
    fi
    ;;

forensics-verify)
    dev="${1:?device required}"; shift
    info "Verifying forensics chain in $dev ..."
    "$GHOSTFS" forensics --device "$dev" verify
    ;;

forensics-tail)
    dev="${1:?device required}"; shift
    n="${1:-100}"; shift || true
    "$GHOSTFS" forensics --device "$dev" tail --count "$n"
    ;;

ids)
    dev="${1:?device required}"; shift
    n="${1:-50}"; shift || true
    info "Last $n IDS alerts from $dev"
    "$GHOSTFS" ids --device "$dev" --count "$n"
    ;;

mac-label)
    dev="${1:?device required}"; shift
    ino="${1:?ino required}"; shift
    level="${1:?level 0..3 required}"; shift
    comps="${1:-0}"; shift || true
    info "Setting MAC label ino=$ino level=$level compartments=$comps"
    "$GHOSTFS" mac --device "$dev" set-label \
        --ino "$ino" --level "$level" --compartments "$comps"
    ok "Label set"
    ;;

mac-clear)
    dev="${1:?device required}"; shift
    uid="${1:?uid required}"; shift
    level="${1:?level 0..3 required}"; shift
    comps="${1:-18446744073709551615}"; shift || true
    trusted=false
    [[ "${1:-}" == "--trusted" ]] && trusted=true && shift || true
    info "Setting clearance uid=$uid level=$level trusted=$trusted"
    trusted_flag=""
    [[ "$trusted" == "true" ]] && trusted_flag="--trusted"
    "$GHOSTFS" mac --device "$dev" set-clearance \
        --uid "$uid" --level "$level" --compartments "$comps" $trusted_flag
    ok "Clearance set"
    ;;

help|--help|-h)
    echo -e "${BOLD}ghostfs-admin.sh${RESET} — GhostFS (cybersec) administration helper"
    echo ""
    echo "  keygen   <outfile>"
    echo "  format   <device> [--passphrase | <keyfile>]"
    echo "  mount    <device> <mountpoint> <keyfile|--passphrase> [rate_MiB=100]"
    echo "  umount   <mountpoint>"
    echo "  audit    <device> [n=50]"
    echo "  quota    <device> <uid> [limit_MiB]"
    echo "  forensics-verify <device>"
    echo "  forensics-tail   <device> [n=100]"
    echo "  ids      <device> [n=50]"
    echo "  mac-label   <device> <ino> <level> [compartments_hex]"
    echo "  mac-clear   <device> <uid> <level> [compartments_hex] [--trusted]"
    echo ""
    echo "  Set GHOSTFS_BIN to override binary path."
    ;;

*)
    die "Unknown command '$cmd'. Run 'ghostfs-admin.sh help'."
    ;;
esac
