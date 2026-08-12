#!/usr/bin/env python3
"""
ghostfs-mkfs — Calamares job module.
Formats the target root partition with GhostFS.

Installed at: /usr/lib/calamares/modules/ghostfs-mkfs/ghostfs_mkfs.py
Configured by: /etc/calamares/modules/ghostfs-mkfs.conf
"""

import os
import secrets
import subprocess

import libcalamares


def get_cfg(key, default=None):
    cfg = libcalamares.job.configuration or {}
    return cfg.get(key, default)


def run():
    """Calamares entry point."""
    gs = libcalamares.globalstorage

    ghostfs_bin   = get_cfg("ghostfsBin", "/usr/local/bin/ghostfs")
    compression   = get_cfg("compression", "zstd")
    cybersec_mode = get_cfg("cybersecMode", False)
    key_dir       = get_cfg("keyDir", "/etc/ghostfs")
    key_filename  = get_cfg("keyFilename", "key.hex")
    block_size    = get_cfg("blockSize", None)

    partitions = gs.value("partitions") or []
    root_device = None
    for p in partitions:
        if p.get("mountPoint") == "/":
            root_device = p.get("device")
            break

    if not root_device:
        return (
            "GhostFS mkfs: no root partition found",
            "partitions globalstorage has no entry with mountPoint='/'. "
            "Did the partition module run before ghostfs-mkfs in settings.conf?",
        )

    libcalamares.utils.debug(f"GhostFS mkfs: formatting {root_device}")

    cmd = [ghostfs_bin, "mkfs", "--device", root_device]
    if block_size:
        cmd += ["--block-size", str(block_size)]

    key_path = None
    if cybersec_mode:
        # Generate a fresh 256-bit key for this install. The passphrase
        # path is intentionally NOT used here — an unattended installer
        # can't safely prompt for (and confirm) a passphrase, so we mint a
        # random key and persist it under keyDir. The user can layer a TPM
        # seal or passphrase-based re-key AFTER first boot via
        # `ghostfs-admin.sh` / `ghostfs tpm-seal-key` if they want typed
        # unlock instead of a bare key file.
        key_hex  = secrets.token_hex(32)
        key_path = os.path.join(key_dir, key_filename)
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        with open(key_path, "w") as f:
            f.write(key_hex)
        os.chmod(key_path, 0o600)
        cmd += ["--key-out", key_path]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return ("GhostFS mkfs failed", result.stderr or result.stdout)

    libcalamares.utils.debug("GhostFS mkfs succeeded")

    gs.insert("ghostfsDevice", root_device)
    gs.insert("ghostfsCompression", compression)
    gs.insert("ghostfsCybersec", bool(cybersec_mode))
    if key_path:
        gs.insert("ghostfsKeyPath", key_path)

    return None
