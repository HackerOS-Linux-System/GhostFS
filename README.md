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

## SIEM integration & dead man's switch (v0.5)

- **`ghostfs siem configure --device <dev> --endpoint host:port [--facility N]`**
  — sends security events (IDS lockouts, canary triggers, chain-integrity
  violations) as standard RFC 5424 syslog over UDP, ingestible by Splunk,
  ELK/Logstash, Graylog, QRadar, etc. out of the box. Zero new dependencies
  (`std::net::UdpSocket`). `ghostfs siem test` sends a one-off test message.
- **Dead man's switch** — every 10 minutes, a background thread re-verifies
  the audit HMAC chain and forensics hash-chain *without* needing anyone to
  run `ghostfs verify` manually. On violation, the volume is immediately
  frozen (all I/O returns `EIO`) and a `CRITICAL`/`Emergency` syslog event
  fires. The freeze flag is deliberately in-memory only, with no live
  "unfreeze" API — recovery is always: investigate offline with
  `ghostfs verify` (doesn't need the live mount), then unmount/remount once
  resolved. This is intentional: a live unfreeze command would let an
  attacker who already has process-level access simply undo the freeze.
- **`frozen` now actually covers all mutating FUSE operations** — previously
  only `read`/`write` checked it; `mkdir`, `rmdir`, `symlink`, `link`,
  `create`, `rename`, `unlink`, `setattr`, `setxattr`, `removexattr` were
  silent gaps in what was supposed to be a full I/O quiesce.
- **Background repair thread was dormant** — it waited forever on a channel
  nothing ever sent to, so the hourly automatic corruption scan never
  actually ran. Fixed to self-schedule via `recv_timeout`.
- **Honeytoken files** (`ghostfs canary mark/unmark/list`) — mark specific
  inodes as bait; any access triggers an immediate critical IDS alert +
  syslog event + optional per-file webhook, and feeds straight into
  `AutoResponse`'s lockout escalation (see v0.4 notes above). Previously
  this CLI existed but called methods that didn't exist anywhere in
  `canary.rs` (which only implemented an unrelated periodic HTTPS beacon).

## Ransomware behavior detection (v0.6)

`security/ransomware.rs` — every write is checked (Shannon entropy of the
raw plaintext GhostFS receives from the client, before its own encryption)
against a per-UID sliding window (60s). If a UID rewrites ≥15 distinct
files with ≥75% of those writes looking high-entropy (≥7.5 bits/byte —
i.e. looking already-encrypted/random, the hallmark of ransomware
overwriting file contents), the **entire volume is immediately frozen**
(not just the offending UID) and an `Emergency` syslog event + IDS alert
fire. This is a behavioral heuristic, not a signature scanner — it can
false-positive on legitimate bulk writes of already-compressed/encrypted
data (backup tools, transcoders, database engines with native page
compression), so known-good UIDs can be exempted:

```
ghostfs ransomware allow --device /dev/sdX1 --uid 1000
ghostfs ransomware status --device /dev/sdX1
ghostfs ransomware disable --device /dev/sdX1   # not recommended
```

Detection alone doesn't undo damage already written before the threshold
tripped — that's what `data/versioning.rs` (previous file versions) and
`ghostfs backup` exist for; this module is one layer of defense-in-depth,
designed to work alongside them, not replace them.

## Two-person integrity & memory hardening (v0.7)

- **`ghostfs shamir split/combine`** — Shamir's Secret Sharing (GF(256),
  same field as AES) for the master key. Split a key file into N shares,
  M of which reconstruct it; fewer than M reveal *zero* information about
  the key (information-theoretic, not just computationally hard). Standard
  "two-person rule" / "no single custodian" control for high-security
  environments. Reconstructed output is a normal `--key-file`, so it drops
  straight into `mount`, `backup`, `restore`, `tpm-seal-key` unchanged.
  ```
  ghostfs shamir split   --key-file key.hex --shares 5 --threshold 3 --output-dir ./shares
  ghostfs shamir combine --share-files s1.txt,s2.txt,s3.txt --output key.hex
  ```
- **Process memory hardening** (`security/memlock.rs`) — `mount`, `keygen`,
  `tpm-seal-key`, and `shamir combine` now call `mlockall()` (keys never
  swapped to disk) and `prctl(PR_SET_DUMPABLE, 0)` (no core dumps, no
  `ptrace` attach by other users, even root without `CAP_SYS_PTRACE`)
  before any key material is read or derived. Best-effort — missing
  `CAP_IPC_LOCK`/low `RLIMIT_MEMLOCK` logs a loud warning instead of
  failing the mount.

## Panic button & live audit streaming (v0.8)

- **`ghostfs lockdown enable/disable/status --device <dev>`** — a true
  cross-process panic button. Unlike `freeze()` (in-memory, one process),
  the lockdown flag lives in the shared sled DB: running `ghostfs lockdown
  enable` from an unrelated CLI invocation takes effect on an *already
  mounted, already running* volume within its next filesystem operation,
  and blocks *everyone including root*, with no exceptions. New mount
  attempts refuse outright while active. Clearing requires an explicit
  `disable`.
- **`ghostfs siem stream-audit --on true`** — optionally streams every
  logged operation (not just security alerts) to the configured SIEM
  endpoint live, as it happens. Defense against an attacker with root who
  deletes the local hash-chained audit/forensics log along with the
  volume — the remote copy already left the building. Opt-in due to
  per-message thread-spawn overhead at high write throughput (use a local
  rsyslog/syslog-ng relay for high-volume workloads).
- **Unencrypted swap warning** — `harden_process()` now also checks
  `/proc/swaps` and warns (once, at mount/keygen time) if active swap
  doesn't look encrypted, since `mlockall()` only protects this process's
  own memory, not swap-based leakage in general.
