#!/usr/bin/env python3
"""
calamares/ghostfs_mkfs.py
─────────────────────────
Calamares job module — formats the target partition with GhostFS.

Place this file and module.desc at:
  /usr/lib/calamares/modules/ghostfs-mkfs/

module.desc:
  ---
  type:      "job"
  name:      "ghostfs-mkfs"
  interface: "python"
  script:    "ghostfs_mkfs.py"
"""

import subprocess
import os
import secrets
import libcalamares


# ─────────────────────────────────────────────────────────────────────────────
# Configuration (override in /etc/calamares/modules/ghostfs-mkfs.conf)
# ─────────────────────────────────────────────────────────────────────────────

def get_cfg(key, default=None):
    cfg = libcalamares.job.configuration or {}
    return cfg.get(key, default)


GHOSTFS_BIN     = get_cfg("ghostfsBin",     "/usr/local/bin/ghostfs")
COMPRESSION     = get_cfg("compression",    "zstd")
CYBERSEC_MODE   = get_cfg("cybersecMode",   False)
KEY_DIR         = get_cfg("keyDir",         "/etc/ghostfs")
KEY_FILENAME    = get_cfg("keyFilename",    "key.hex")
BLOCK_SIZE      = get_cfg("blockSize",      None)


# ─────────────────────────────────────────────────────────────────────────────
def run():
    """Calamares entry point."""
    gs = libcalamares.globalstorage

    # Determine root partition
    partitions = gs.value("partitions") or []
    root_device = None
    for p in partitions:
        if p.get("mountPoint") == "/":
            root_device = p.get("device")
            break

    if not root_device:
        return ("GhostFS mkfs: no root partition found",
                "partitions globalstorage has no entry with mountPoint='/'")

    libcalamares.utils.debug(f"GhostFS mkfs: formatting {root_device}")

    # ── Format ────────────────────────────────────────────────────────────────
    cmd = [GHOSTFS_BIN, "mkfs", "--device", root_device]
    if BLOCK_SIZE:
        cmd += ["--block-size", str(BLOCK_SIZE)]
    if CYBERSEC_MODE:
        cmd += ["--encryption"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return ("GhostFS mkfs failed",
                result.stderr or result.stdout)

    libcalamares.utils.debug("GhostFS mkfs succeeded")

    # ── Generate key for cybersec installs ────────────────────────────────────
    if CYBERSEC_MODE:
        key_hex  = secrets.token_hex(32)                     # 256-bit key
        key_path = os.path.join(KEY_DIR, KEY_FILENAME)

        os.makedirs(KEY_DIR, mode=0o700, exist_ok=True)
        with open(key_path, "w") as f:
            f.write(key_hex)
        os.chmod(key_path, 0o600)

        # Share the key path with the mount module via globalstorage
        gs.insert("ghostfsKeyPath", key_path)
        gs.insert("ghostfsCybersec", True)
        libcalamares.utils.debug(f"GhostFS: generated key at {key_path}")
    else:
        gs.insert("ghostfsCybersec", False)

    gs.insert("ghostfsDevice",      root_device)
    gs.insert("ghostfsCompression", COMPRESSION)
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  Separate mount module
# ─────────────────────────────────────────────────────────────────────────────

"""
calamares/ghostfs_mount.py
──────────────────────────
Calamares job module — mounts the freshly-formatted GhostFS root so the
installer can copy files onto it.

Place alongside module.desc at:
  /usr/lib/calamares/modules/ghostfs-mount/
"""

def mount_run():
    gs    = libcalamares.globalstorage
    root  = gs.value("rootMountPoint")
    dev   = gs.value("ghostfsDevice")
    comp  = gs.value("ghostfsCompression") or "zstd"
    csec  = gs.value("ghostfsCybersec")    or False
    key   = gs.value("ghostfsKeyPath")     or ""

    if not dev:
        return ("GhostFS mount: device not set in globalstorage",
                "Run ghostfs-mkfs before ghostfs-mount")

    os.makedirs(root, exist_ok=True)

    cmd = [
        GHOSTFS_BIN, "mount",
        "--device", dev,
        "--mountpoint", root,
        "--compression", comp,
        "--noatime",
    ]
    if csec and key:
        cmd += ["--cybersecurity", "--key-file", key]

    libcalamares.utils.debug(f"GhostFS mount: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    # FUSE mounts background themselves — give it a moment
    import time
    time.sleep(2)

    # Verify mount appeared
    verify = subprocess.run(["mount"], capture_output=True, text=True)
    if "ghostfs" not in verify.stdout:
        return ("GhostFS mount failed",
                result.stderr or "mount not found after 2s")

    libcalamares.utils.debug("GhostFS mount succeeded")
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  Separate umount module
# ─────────────────────────────────────────────────────────────────────────────

def umount_run():
    gs   = libcalamares.globalstorage
    root = gs.value("rootMountPoint")

    result = subprocess.run(
        [GHOSTFS_BIN, "umount", "--mountpoint", root],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        # Non-fatal — log and continue
        libcalamares.utils.warning(
            f"GhostFS umount returned {result.returncode}: {result.stderr}"
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  fstab helper
# ─────────────────────────────────────────────────────────────────────────────

def fstab_entry(device: str, mountpoint: str, compression: str = "zstd") -> str:
    """
    Return a GhostFS /etc/fstab line.
    Called from a custom fstab Calamares module or post-install hook.
    """
    options = f"noatime,compression={compression}"
    return f"{device}\t{mountpoint}\tghostfs\t{options}\t0\t0\n"
