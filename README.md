# GhostFS
File system for HackerOS

## What is GhostFS ?
It is a file system as an alternative to ext4 or other file systems but aimed at cybersecurity.

GhostFS was formerly also known as HackerFS.

## Backup & Restore

Full or incremental encrypted backups to a single portable file:

```
ghostfs backup  --device /path/to/vol --output vault.gfsbackup --passphrase
ghostfs restore --input vault.gfsbackup --device /path/to/new-vol --passphrase
ghostfs backup-info --input vault.gfsbackup
```

By default the backup file is encrypted with the volume's own wrapping key
(same passphrase/key-file unlocks both); pass `--backup-passphrase` to use a
separate secret for the backup file itself (recommended if the backup will
be stored with a third party). Incremental backups (`--since-seq` +
`--changed-inodes`, sourced from `ghostfs forensics tail`) only export the
inodes that changed, for fast periodic snapshots. See
`source-code/data/backup.rs` for the on-disk format.

## Early-boot unlock (TPM) & recovery mode

```
ghostfs tpm-seal-key --key-file key.hex --output sealed.bin --pcr 7
ghostfs mount --device /dev/sdX1 --mountpoint /mnt --sealed-key-file sealed.bin --tpm-pcr 7
```

The initramfs boot hook (`scripts/ghostfs-mount-initramfs`) tries, in order:
TPM unseal (silent, `ghostfs.tpm=1`) → interactive passphrase prompt (up to
3 attempts, via plymouth splash if active) → a minimal recovery shell if
both fail, so a bad TPM state or forgotten passphrase never leaves you at a
dead black screen. Force the passphrase path (skip TPM) with
`ghostfs.recovery=1` on the kernel command line — useful after a BIOS/kernel
update invalidates the sealed PCR value.

## Installing as the default root filesystem (Calamares)

The `.deb` built by `.github/workflows/build.yml` installs GhostFS *and*
patches an already-installed Calamares so its graphical installer offers
**only** GhostFS as a root filesystem — see
`packaging/deb/usr/share/doc/ghostfs/README-calamares.md`.

## Read-ahead / prefetch

Sequential reads are detected per-inode and the next few blocks are
decrypted/decompressed ahead of time on a small `rayon` thread pool
(`source-code/core/prefetch.rs`), populating the LRU cache before the FUSE
layer asks for them.

## Cybersecurity hardening (v0.4)

Fixes and additions focused specifically on the "cybersecurity filesystem"
claim — not new features so much as closing gaps between the marketing and
the implementation:

- **`volume_uuid` persistence** — previously regenerated randomly on every
  mount, which silently made data written in one session undecryptable in
  the next (AAD mismatch). Now persisted in the HMAC-protected superblock.
- **Fail-closed mount** — a wrong passphrase/key-file used to mount
  successfully and only fail on the first block read. `GhostFS::new` now
  verifies the superblock HMAC up front and refuses to mount on mismatch.
  `ghostfs mount --strict` additionally verifies the audit HMAC chain and
  forensics chain-of-custody before mounting.
- **`ghostfs verify`** — full offline security self-test (superblock HMAC,
  audit chain, forensics chain, IDS alert summary, full block-level
  integrity scan) without mounting the volume at all.
- **Nonce hardening** — AES-256-GCM nonces are now `session-random-prefix
  || monotonic-counter` instead of pure-random, eliminating birthday-bound
  collision risk entirely rather than just making it statistically small.
- **Encrypted directory entries** — filenames were previously stored as
  **plaintext base64 directly in the sled key** (trivially reversible) with
  an *unkeyed* hash alongside them (vulnerable to filename dictionary
  attacks). Now: a keyed blind index for O(1) lookup + AES-256-GCM for the
  recoverable name, both derived from the master key.
- **TPM software-fallback fix** — the no-TPM dev/test path used a broken
  XOR "seal" that `unseal` could not actually reverse. Replaced with a real
  (machine-id-bound) AES-256-GCM seal/unseal, still clearly logged as
  non-hardware-backed.
- **IDS auto-response** — repeated alerts for the same UID within 15
  minutes now escalate automatically: a loud warning at 3 alerts, and a
  full UID lockout (fail-closed on every subsequent op, persisted across
  remounts) at 6. MAC policy denials now also feed the IDS instead of only
  going to `log::debug!`. Manage with `ghostfs ids list|lock|unlock|list-locked`.
