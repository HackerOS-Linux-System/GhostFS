#!/usr/bin/env python3
"""
ghostfs-umount — Calamares job module.
Cleanly unmounts the GhostFS root at the end of the install sequence
(after bootloader/initramfs steps have written everything they need).

Installed at: /usr/lib/calamares/modules/ghostfs-umount/ghostfs_umount.py
"""

import subprocess

import libcalamares


def get_cfg(key, default=None):
    cfg = libcalamares.job.configuration or {}
    return cfg.get(key, default)


def run():
    gs = libcalamares.globalstorage
    ghostfs_bin = get_cfg("ghostfsBin", "/usr/local/bin/ghostfs")
    root = gs.value("rootMountPoint")

    if not root:
        return None  # nothing to unmount

    result = subprocess.run(
        [ghostfs_bin, "umount", "--mountpoint", root],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        # Non-fatal — log and continue; a failed unmount here doesn't mean
        # the installed system is broken (it can be unmounted by init
        # anyway), but it's worth surfacing for postmortem debugging.
        libcalamares.utils.warning(
            f"GhostFS umount returned {result.returncode}: {result.stderr}"
        )
    return None
