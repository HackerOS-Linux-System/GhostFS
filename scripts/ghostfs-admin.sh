#!/usr/bin/env bash
# ghostfs-admin.sh — GhostFS administration helper
# Wraps common ghostfs CLI operations with sane defaults and coloured output.
#
# Usage: ghostfs-admin.sh <command> [options]
# Commands:
#   format   <device>                        — format a new volume
#   mount    <device> <mountpoint> [key]     — mount (key optional, normal mode)
#   mount-cs <device> <mountpoint> <keyfile> — mount cybersec mode
#   umount   <mountpoint>                    — unmount
#   audit    <device> [n]                    — show last n audit entries (default 50)
#   quota    <device> <uid> [limit_mb]       — show or set quota
#   forensics-verify <device>                — verify cybersec forensics chain
#   forensics-tail   <device> [n]            — show last n forensics entries
#   ids      <device> [n]                    — show last n IDS alerts
#   mac-label   <device> <ino> <level> [compartments_hex]
#   mac-clear   <device> <uid>  <level> [compartments_hex] [--trusted]
#   keygen   <outfile>                       — generate a fresh 256-bit key

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET} $*"; }
ok()    { echo -e "${GREEN}[ OK ]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
die()   { echo -e "${RED}[ERR ]${RESET} $*" >&2; exit 1; }

GHOSTFS="${GHOSTFS_BIN:-ghostfs}"
command -v "$GHOSTFS" &>/dev/null || die "ghostfs binary not found. Set GHOSTFS_BIN or install to PATH."

cmd="${1:-help}"; shift || true

case "$cmd" in

# ── format ──────────────────────────────────────────────────────────────────
format)
    dev="${1:?device required}"; shift
    info "Formatting GhostFS volume at $dev ..."
    "$GHOSTFS" mkfs --device "$dev"
    ok "Formatted $dev"
    ;;

# ── mount (normal) ──────────────────────────────────────────────────────────
mount)
    dev="${1:?device required}"; shift
    mnt="${1:?mountpoint required}"; shift
    key="${1:-}"; shift || true
    mkdir -p "$mnt"
    args=(mount --device "$dev" --mountpoint "$mnt" --compression zstd --noatime)
    if [[ -n "$key" ]]; then
        args+=(--cybersecurity --key-file "$key")
        info "Mounting $dev → $mnt (normal+encrypted)"
    else
        info "Mounting $dev → $mnt (normal)"
    fi
    "$GHOSTFS" "${args[@]}" &
    sleep 1
    mount | grep -q ghostfs && ok "Mounted at $mnt" || die "Mount failed"
    ;;

# ── mount (cybersec) ────────────────────────────────────────────────────────
mount-cs)
    dev="${1:?device required}"; shift
    mnt="${1:?mountpoint required}"; shift
    key="${1:?key file required}"; shift
    [[ -r "$key" ]] || die "Key file $key not readable"
    mkdir -p "$mnt"
    info "Mounting $dev → $mnt [CYBERSEC MODE]"
    "$GHOSTFS" mount \
        --device "$dev" --mountpoint "$mnt" \
        --cybersecurity --key-file "$key" \
        --compression zstd --noatime &
    sleep 1
    mount | grep -q ghostfs && ok "Cybersec mount at $mnt" || die "Mount failed"
    ;;

# ── umount ───────────────────────────────────────────────────────────────────
umount)
    mnt="${1:?mountpoint required}"; shift
    info "Unmounting $mnt ..."
    "$GHOSTFS" umount --mountpoint "$mnt"
    ok "Unmounted $mnt"
    ;;

# ── audit ────────────────────────────────────────────────────────────────────
audit)
    dev="${1:?device required}"; shift
    n="${1:-50}"; shift || true
    info "Last $n audit entries from $dev"
    "$GHOSTFS" audit --device "$dev" tail --count "$n"
    ;;

# ── quota show / set ─────────────────────────────────────────────────────────
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

# ── forensics verify ─────────────────────────────────────────────────────────
forensics-verify)
    dev="${1:?device required}"; shift
    info "Verifying forensics chain in $dev ..."
    "$GHOSTFS" forensics --device "$dev" verify
    ;;

# ── forensics tail ────────────────────────────────────────────────────────────
forensics-tail)
    dev="${1:?device required}"; shift
    n="${1:-100}"; shift || true
    "$GHOSTFS" forensics --device "$dev" tail --count "$n"
    ;;

# ── ids alerts ────────────────────────────────────────────────────────────────
ids)
    dev="${1:?device required}"; shift
    n="${1:-50}"; shift || true
    info "Last $n IDS alerts from $dev"
    "$GHOSTFS" ids --device "$dev" --count "$n"
    ;;

# ── mac label ─────────────────────────────────────────────────────────────────
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

# ── mac clearance ─────────────────────────────────────────────────────────────
mac-clear)
    dev="${1:?device required}"; shift
    uid="${1:?uid required}"; shift
    level="${1:?level 0..3 required}"; shift
    comps="${1:-18446744073709551615}"; shift || true  # 0xFFFF... = all compartments
    trusted=false
    [[ "${1:-}" == "--trusted" ]] && trusted=true && shift || true
    info "Setting clearance uid=$uid level=$level trusted=$trusted"
    trusted_flag=""
    [[ "$trusted" == "true" ]] && trusted_flag="--trusted"
    "$GHOSTFS" mac --device "$dev" set-clearance \
        --uid "$uid" --level "$level" --compartments "$comps" $trusted_flag
    ok "Clearance set"
    ;;

# ── keygen ────────────────────────────────────────────────────────────────────
keygen)
    out="${1:?output file required}"; shift
    [[ -e "$out" ]] && die "$out already exists — refusing to overwrite"
    openssl rand -hex 32 > "$out"
    chmod 600 "$out"
    ok "256-bit key written to $out"
    echo -e "${YELLOW}  ⚠  Keep this file safe. Losing it means losing all data.${RESET}"
    ;;

# ── help ──────────────────────────────────────────────────────────────────────
help|--help|-h)
    echo -e "${BOLD}ghostfs-admin.sh${RESET} — GhostFS administration helper"
    echo ""
    echo "  format   <device>"
    echo "  mount    <device> <mountpoint> [keyfile]"
    echo "  mount-cs <device> <mountpoint> <keyfile>   (cybersec build)"
    echo "  umount   <mountpoint>"
    echo "  audit    <device> [n=50]"
    echo "  quota    <device> <uid> [limit_MiB]"
    echo "  forensics-verify <device>                  (cybersec build)"
    echo "  forensics-tail   <device> [n=100]          (cybersec build)"
    echo "  ids      <device> [n=50]                   (cybersec build)"
    echo "  mac-label   <device> <ino> <level> [compartments_hex]"
    echo "  mac-clear   <device> <uid> <level> [compartments_hex] [--trusted]"
    echo "  keygen   <outfile>"
    echo ""
    echo "  Set GHOSTFS_BIN to override the ghostfs binary path."
    ;;

*)
    die "Unknown command '$cmd'. Run 'ghostfs-admin.sh help'."
    ;;
esac
