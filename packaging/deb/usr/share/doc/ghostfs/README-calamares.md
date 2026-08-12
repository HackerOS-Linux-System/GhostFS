# GhostFS + Calamares (.deb integration)

This package (`ghostfs`) is built by `.github/workflows/build.yml` and does
two things on install:

1. Installs the `ghostfs` / `ghostfs-cybersec` binaries, `ghostfs-admin.sh`,
   the `/sbin/mount.ghostfs` helper (so plain `mount -t ghostfs ...` and
   `/etc/fstab` entries work), and the initramfs early-boot hooks.
2. **Patches your already-installed Calamares configuration** so the
   graphical installer offers GhostFS as the **only** root filesystem —
   no ext4, no btrfs, no xfs. This is done by
   `/usr/lib/ghostfs/calamares-patch.py`, called from `postinst`:
   - `/etc/calamares/settings.conf` is replaced with a GhostFS-aware job
     sequence (`ghostfs-mkfs` → `ghostfs-mount` → `unpackfs` → ... →
     `ghostfs-umount`). Your original file is saved as
     `settings.conf.ghostfs-orig`.
   - `/etc/calamares/modules/partition.conf` is merged with
     `availableFileSystemTypes: [ghostfs]` and
     `defaultFileSystemType: ghostfs`. Your original file is saved as
     `partition.conf.ghostfs-orig`.

Both patches are **reverted automatically** if you `apt remove ghostfs` /
`apt purge ghostfs` (see `postrm`) — your Calamares installer goes back to
its original ext4/btrfs behaviour.

## Requirements

- Calamares must already be installed (`Depends: calamares (>= 3.2)` in
  `DEBIAN/control` — apt will pull it in if it's missing).
- `python3-yaml` is needed for the `partition.conf` merge step. If it's
  missing, `postinst` prints a warning and skips that specific patch
  (the rest of the install still succeeds) rather than failing the whole
  package install.

## Manual re-application

If you edit `/etc/calamares/modules/partition.conf` by hand afterwards and
want to re-apply the GhostFS restriction:

```
sudo python3 /usr/lib/ghostfs/calamares-patch.py apply
```

## Using GhostFS outside the installer

Once the package is installed, GhostFS also works as a normal FUSE
filesystem on an already-running system:

```
# Format + mount a volume by hand
sudo ghostfs-admin.sh format /dev/sdb1 --passphrase
sudo ghostfs-admin.sh mount  /dev/sdb1 /mnt/vault --passphrase

# Or via /etc/fstab (uses the /sbin/mount.ghostfs helper):
#   /dev/sdb1  /mnt/vault  ghostfs  noatime,compression=zstd,key-file=/etc/ghostfs/vault.hex  0  0
```

See the top-level `README.md` for backup/restore (`ghostfs backup` /
`ghostfs restore`) and TPM-sealed early-boot unlock
(`ghostfs tpm-seal-key`, `ghostfs.tpm=1` kernel parameter).
