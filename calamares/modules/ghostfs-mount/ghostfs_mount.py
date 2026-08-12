#!/usr/bin/env python3
"""
ghostfs-mount — Calamares job module.
Mounts the freshly-formatted GhostFS root so `unpackfs` can copy the live
system onto it.

Installed at: /usr/lib/calamares/modules/ghostfs-mount/ghostfs_mount.py
Reads globalstorage keys set by ghostfs-mkfs: ghostfsDevice,
ghostfsCompression, ghostfsCybersec, ghostfsKeyPath.
"""

import os
import subprocess
import time

import libcalamares


def get_cfg(key, default=None):
    cfg = libcalamares.job.configuration or {}
    return cfg.get(key, default)


def run():
    gs = libcalamares.globalstorage

    ghostfs_bin = get_cfg("ghostfsBin", "/usr/local/bin/ghostfs")
    root  = gs.value("rootMountPoint")
    dev   = gs.value("ghostfsDevice")
    comp  = gs.value("ghostfsCompression") or "zstd"
    csec  = gs.value("ghostfsCybersec") or False
    key   = gs.value("ghostfsKeyPath") or ""

    if not dev:
        return (
            "GhostFS mount: device not set in globalstorage",
            "Run ghostfs-mkfs before ghostfs-mount in settings.conf sequence",
        )
    if not root:
        return ("GhostFS mount: rootMountPoint not set", "Calamares partition module did not set it")

    os.makedirs(root, exist_ok=True)

    cmd = [
        ghostfs_bin, "mount",
        "--device", dev,
        "--mountpoint", root,
        "--compression", comp,
        "--noatime",
    ]
    if csec and key:
        cmd += ["--key-file", key]

    libcalamares.utils.debug(f"GhostFS mount: {' '.join(cmd)}")
    # ghostfs mount (via fuser) backgrounds the FUSE loop itself once the
    # mount syscall succeeds, so Popen (not run) — we don't want to block
    # the installer thread for the lifetime of the mount.
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    mounted = False
    for _ in range(20):
        time.sleep(0.5)
        verify = subprocess.run(["mount"], capture_output=True, text=True)
        if "ghostfs" in verify.stdout and root in verify.stdout:
            mounted = True
            break
        if proc.poll() is not None and proc.returncode != 0:
            _, stderr = proc.communicate()
            return ("GhostFS mount failed", stderr.decode(errors="replace"))

    if not mounted:
        return ("GhostFS mount timed out", f"No ghostfs mount found at {root} after 10s")

    libcalamares.utils.debug("GhostFS mount succeeded")
    return None
