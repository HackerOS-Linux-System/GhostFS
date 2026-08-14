#!/usr/bin/env python3
"""
calamares-patch.py — apply / revert the GhostFS patch to an EXISTING
Calamares installation's configuration.

Called by DEBIAN/postinst (mode=apply) and DEBIAN/postrm (mode=revert).
Never fails the package install/removal outright on a patch error — an
installer that still offers ext4 as a fallback is a soft failure, not a
broken system — but it prints a loud warning either way.

What it touches:
  /etc/calamares/settings.conf          — replaced wholesale with the
                                           GhostFS-aware sequence shipped at
                                           /usr/share/doc/ghostfs/settings.conf.ghostfs
                                           (backed up first).
  /etc/calamares/modules/partition.conf — merged (not replaced) with the
                                           key/value pairs from
                                           /usr/share/doc/ghostfs/partition.conf.ghostfs-patch.yaml
                                           (original values backed up so they
                                           can be restored verbatim on revert).
"""

import shutil
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print(
        "calamares-patch.py: PyYAML not available — cannot safely merge "
        "partition.conf. Install python3-yaml and re-run:\n"
        "  python3 /usr/lib/ghostfs/calamares-patch.py apply",
        file=sys.stderr,
    )
    sys.exit(0)  # non-fatal — see module docstring

CALAMARES_ETC = Path("/etc/calamares")
SETTINGS_CONF = CALAMARES_ETC / "settings.conf"
PARTITION_CONF = CALAMARES_ETC / "modules" / "partition.conf"

DOC_DIR = Path("/usr/share/doc/ghostfs")
NEW_SETTINGS = DOC_DIR / "settings.conf.ghostfs"
PARTITION_PATCH = DOC_DIR / "partition.conf.ghostfs-patch.yaml"

SETTINGS_BACKUP = CALAMARES_ETC / "settings.conf.ghostfs-orig"
PARTITION_BACKUP = CALAMARES_ETC / "modules" / "partition.conf.ghostfs-orig"

MARKER = "# ghostfs-patch-applied: do not edit availableFileSystemTypes below by hand\n"


def apply_patch():
    if not CALAMARES_ETC.is_dir():
        print("calamares-patch.py: /etc/calamares not found — is Calamares actually installed? "
              "Skipping (this package Depends: calamares, so this shouldn't normally happen).",
              file=sys.stderr)
        return

    # ── settings.conf: full replace, backed up once ──────────────────────────
    if SETTINGS_CONF.exists() and not SETTINGS_BACKUP.exists():
        shutil.copy2(SETTINGS_CONF, SETTINGS_BACKUP)
        print(f"calamares-patch.py: backed up {SETTINGS_CONF} -> {SETTINGS_BACKUP}")

    if NEW_SETTINGS.exists():
        shutil.copy2(NEW_SETTINGS, SETTINGS_CONF)
        print(f"calamares-patch.py: installed GhostFS sequence -> {SETTINGS_CONF}")
    else:
        print(f"calamares-patch.py: {NEW_SETTINGS} missing — settings.conf NOT patched", file=sys.stderr)

    # ── partition.conf: merge, original values backed up as a raw copy ───────
    if not PARTITION_CONF.exists():
        print(f"calamares-patch.py: {PARTITION_CONF} not found — nothing to merge into, "
              "creating a minimal one with just the GhostFS keys.", file=sys.stderr)
        PARTITION_CONF.parent.mkdir(parents=True, exist_ok=True)
        current = {}
    else:
        if not PARTITION_BACKUP.exists():
            shutil.copy2(PARTITION_CONF, PARTITION_BACKUP)
            print(f"calamares-patch.py: backed up {PARTITION_CONF} -> {PARTITION_BACKUP}")
        with open(PARTITION_CONF) as f:
            current = yaml.safe_load(f) or {}

    if not PARTITION_PATCH.exists():
        print(f"calamares-patch.py: {PARTITION_PATCH} missing — partition.conf NOT patched", file=sys.stderr)
        return

    with open(PARTITION_PATCH) as f:
        patch = yaml.safe_load(f) or {}

    current.update(patch)

    with open(PARTITION_CONF, "w") as f:
        f.write(MARKER)
        yaml.safe_dump(current, f, default_flow_style=False, sort_keys=False)

    print(f"calamares-patch.py: merged GhostFS-only filesystem settings -> {PARTITION_CONF}")
    print("calamares-patch.py: Calamares will now offer ONLY ghostfs as a root filesystem.")


def revert_patch():
    restored_any = False

    if SETTINGS_BACKUP.exists():
        shutil.copy2(SETTINGS_BACKUP, SETTINGS_CONF)
        SETTINGS_BACKUP.unlink()
        print(f"calamares-patch.py: restored original {SETTINGS_CONF}")
        restored_any = True

    if PARTITION_BACKUP.exists():
        shutil.copy2(PARTITION_BACKUP, PARTITION_CONF)
        PARTITION_BACKUP.unlink()
        print(f"calamares-patch.py: restored original {PARTITION_CONF}")
        restored_any = True

    if not restored_any:
        print("calamares-patch.py: no backups found — nothing to revert "
              "(package was likely installed without Calamares present, or "
              "configs were already reverted).")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("apply", "revert"):
        print("usage: calamares-patch.py {apply|revert}", file=sys.stderr)
        sys.exit(1)
    if sys.argv[1] == "apply":
        apply_patch()
    else:
        revert_patch()


if __name__ == "__main__":
    main()
