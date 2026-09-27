use rand;
use sled;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use fuser::MountOption;
use hex;
use bincode;
use blake3;

use ghostfs::{
    GhostFS,
    crypto::{Key, Crypto},
    audit::Audit,
    quota::Quota,
    forensics::Forensics,
    ids::Ids,
    mac::{MacLabels, MacLabel, MacClearance, SensitivityLevel},
    canary::{Canary, CanaryConfig},
    kdf::{self, KdfParams},
    superblock::Superblock,
    rate_limit::RateLimiter,
    backup::Backup,
    compression::{Compression, CompressionType},
    deduplication::Deduplication,
    versioning::Versioning,
    repair::Repair,
};

#[derive(Parser)]
#[command(name = "ghostfs", version = "0.3.0", about = "GhostFS — cybersecurity filesystem for HackerOS")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount a GhostFS volume (encryption always on)
    Mount {
        #[arg(short, long)] device:     PathBuf,
        #[arg(short, long)] mountpoint: PathBuf,
        #[arg(long, conflicts_with_all = ["passphrase", "sealed_key_file"])] key_file:   Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["key_file", "sealed_key_file"])]   passphrase: Option<String>,
        /// TPM-sealed key blob (produced by `ghostfs tpm seal`) — used for
        /// early-boot unlock from initramfs. Falls back to software
        /// unseal (NO hardware protection) if no TPM is present; see
        /// security/tpm.rs. Conflicts with --key-file/--passphrase.
        #[arg(long, conflicts_with_all = ["key_file", "passphrase"])] sealed_key_file: Option<PathBuf>,
        /// PCR index the sealed key is bound to (required with --sealed-key-file).
        #[arg(long, default_value_t = 7)] tpm_pcr: u32,
        #[arg(long)] compression:   Option<String>,
        #[arg(long)] noatime:       bool,
        #[arg(long)] allow_other:   bool,
        #[arg(long, default_value_t = 100)] rate_limit_mb: u64,
        /// Refuse to mount unless the audit HMAC chain AND forensics
        /// chain-of-custody log both verify intact. Superblock HMAC is
        /// ALWAYS checked (fail-closed) regardless of this flag — this
        /// flag adds the (slower, O(log size)) extra checks on top.
        #[arg(long)] strict: bool,
    },

    /// Seal a raw 256-bit key file against the TPM (or software fallback)
    /// bound to a PCR value — used to enable early-boot unlock without a
    /// typed passphrase. See `scripts/ghostfs-mount-initramfs`.
    TpmSealKey {
        #[arg(long)] key_file: PathBuf,
        #[arg(long)] output:   PathBuf,
        #[arg(long, default_value_t = 7)] pcr: u32,
    },

    /// Format (initialise) a new GhostFS volume
    Mkfs {
        #[arg(short, long)] device:         PathBuf,
        #[arg(long)]        key_out:        Option<PathBuf>,
        /// Wymuś podanie hasła interaktywnie (z potwierdzeniem, bez echa)
        #[arg(long)]        passphrase:     Option<String>,
        /// Wymuś interaktywne hasło z potwierdzeniem (jeśli --passphrase nie podane)
        #[arg(long)]        interactive_passphrase: bool,
        #[arg(long, default_value_t = 65536)] kdf_memory:    u32,
        #[arg(long, default_value_t = 3)]     kdf_iterations: u32,
        #[arg(long)]        block_size:     Option<u32>,
    },

    /// Unmount a GhostFS volume
    Umount { #[arg(short, long)] mountpoint: PathBuf },

    Audit {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: AuditCommands,
    },

    Quota {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: QuotaCommands,
    },

    Forensics {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: ForensicsCommands,
    },

    Ids {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: IdsCommands,
    },

    Mac {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: MacCommands,
    },

    /// Manual panic button — deny ALL access (including root) on this
    /// volume, on every current and future mount, until explicitly
    /// disabled. See security/response.rs::enable_global_lockdown.
    Lockdown {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: LockdownCommands,
    },

    /// Shamir's Secret Sharing — split a key file into N shares, M of which
    /// are needed to reconstruct it. See security/shamir.rs.
    Shamir {
        #[command(subcommand)] action: ShamirCommands,
    },

    /// Ransomware behavior detection — see security/ransomware.rs.
    Ransomware {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: RansomwareCommands,
    },

    /// SIEM integration (syslog RFC 5424) — see security/syslog.rs.
    Siem {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: SiemCommands,
    },

    /// WORM / immutable file protection — see security/worm.rs.
    Worm {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: WormCommands,
    },

    /// Manage canary (honeypot) files
    Canary {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: CanaryCommands,
    },

    Keygen { #[arg(short, long)] output: PathBuf },

    /// Export a full or incremental encrypted backup of a volume to a single portable file.
    Backup {
        #[arg(short, long)] device: PathBuf,
        #[arg(short, long)] output: PathBuf,
        #[arg(long, conflicts_with = "passphrase")] key_file:   Option<PathBuf>,
        #[arg(long, conflicts_with = "key_file")]   passphrase: Option<String>,
        /// Osobne hasło do zaszyfrowania SAMEGO pliku backupu (opcjonalne —
        /// domyślnie używany jest wewnętrzny wrapping_key wolumenu).
        #[arg(long)] backup_passphrase: Option<String>,
        /// Backup przyrostowy: tylko inode zmienione po tym seq numerze
        /// forensics logu (zobacz `ghostfs forensics tail`).
        #[arg(long)] since_seq: Option<u64>,
        /// Wymagane przy --since-seq: lista inode do dołączenia (comma-separated).
        #[arg(long, value_delimiter = ',')] changed_inodes: Vec<u64>,
    },

    /// Restore an encrypted backup file into a brand-new volume (device must not exist).
    Restore {
        #[arg(short, long)] input:  PathBuf,
        #[arg(short, long)] device: PathBuf,
        #[arg(long, conflicts_with = "passphrase")] key_file:   Option<PathBuf>,
        #[arg(long, conflicts_with = "key_file")]   passphrase: Option<String>,
        #[arg(long)] backup_passphrase: Option<String>,
    },

    /// Show metadata about a backup file without restoring it.
    BackupInfo { #[arg(short, long)] input: PathBuf },

    /// Full offline security self-test: superblock HMAC, audit log HMAC
    /// chain, forensics chain-of-custody, and a per-block integrity-tree
    /// scan (blake3 leaves vs stored data, dedup refcounts). Does NOT
    /// mount the volume — safe to run on a volume that's suspected to be
    /// compromised/tampered, without giving anything FUSE-level access.
    Verify {
        #[arg(short, long)] device: PathBuf,
        #[arg(long, conflicts_with = "passphrase")] key_file:   Option<PathBuf>,
        #[arg(long, conflicts_with = "key_file")]   passphrase: Option<String>,
        /// Skip the full block-level integrity scan (only checks
        /// superblock/audit/forensics — much faster on large volumes).
        #[arg(long)] quick: bool,
    },
}

#[derive(Subcommand)]
enum AuditCommands {
    Tail { #[arg(short, long, default_value_t = 100)] count: usize },
    /// Weryfikuj podpisy HMAC bloków audit logu (wymaga --key-file lub --passphrase)
    VerifySig {
        #[arg(long)] key_file:   Option<PathBuf>,
        #[arg(long)] passphrase: Option<String>,
    },
}

#[derive(Subcommand)]
enum QuotaCommands {
    Set  { #[arg(long)] uid: u32, #[arg(long)] limit: u64 },
    Show { #[arg(long)] uid: u32 },
}

#[derive(Subcommand)]
enum ForensicsCommands {
    Verify,
    Tail { #[arg(short, long, default_value_t = 100)] count: usize },
    /// Export the full chain-of-custody log to a file, signed with the
    /// volume's Ed25519 key — verifiable by a third party without any
    /// access to the volume itself (see `ghostfs forensics signing-key`).
    Export {
        #[arg(short, long)] output: PathBuf,
        #[arg(long, conflicts_with = "passphrase")] key_file:   Option<PathBuf>,
        #[arg(long, conflicts_with = "key_file")]   passphrase: Option<String>,
    },
    /// Verify a previously exported signed log — needs ONLY the exported
    /// file itself (public key + signature are embedded in it). Does NOT
    /// open, mount, or even touch the original volume.
    VerifyExport { #[arg(short, long)] input: PathBuf },
    /// Print this volume's Ed25519 public key (hex) — hand this to an
    /// auditor/court ONCE, ahead of time, out-of-band, so future signed
    /// exports can be verified as genuinely coming from this volume.
    SigningKey {
        #[arg(long, conflicts_with = "passphrase")] key_file:   Option<PathBuf>,
        #[arg(long, conflicts_with = "key_file")]   passphrase: Option<String>,
    },
}

#[derive(Subcommand)]
enum MacCommands {
    SetLabel {
        #[arg(long)] ino: u64,
        #[arg(long)] level: u8,
        #[arg(long, default_value_t = 0)] compartments: u64,
    },
    SetClearance {
        #[arg(long)] uid: u32,
        #[arg(long)] level: u8,
        #[arg(long, default_value_t = u64::MAX)] compartments: u64,
        #[arg(long)] trusted: bool,
    },
    ShowLabel     { #[arg(long)] ino: u64 },
    ShowClearance { #[arg(long)] uid: u32 },
}

#[derive(Subcommand)]
enum CanaryCommands {
    /// Oznacz inode jako plik canary (honeypot)
    Mark {
        #[arg(long)] ino: u64,
        #[arg(long)] description: String,
        /// Opcjonalny URL beacon HTTP (np. http://collector.local:8080/alert)
        #[arg(long)] beacon_url: Option<String>,
    },
    Unmark { #[arg(long)] ino: u64 },
    List,
}

#[derive(Subcommand)]
enum LockdownCommands {
    Enable  { #[arg(long)] reason: String },
    Disable,
    Status,
}

#[derive(Subcommand)]
enum ShamirCommands {
    /// Split a 32-byte hex key file into N shares, M needed to reconstruct.
    Split {
        #[arg(long)] key_file:   PathBuf,
        #[arg(long)] shares:     u8,
        #[arg(long)] threshold:  u8,
        #[arg(long)] output_dir: PathBuf,
    },
    /// Reconstruct a key file from >= threshold share files.
    Combine {
        #[arg(long, value_delimiter = ',')] share_files: Vec<PathBuf>,
        #[arg(long)] output: PathBuf,
    },
}

#[derive(Subcommand)]
enum RansomwareCommands {
    Enable,
    Disable,
    /// Exempt a UID from detection (backup/transcode/compression tools —
    /// legitimately write lots of high-entropy data in bulk).
    Allow    { #[arg(long)] uid: u32 },
    Disallow { #[arg(long)] uid: u32 },
}

#[derive(Subcommand)]
enum SiemCommands {
    /// Configure the syslog endpoint (host:port, UDP) events are sent to.
    Configure {
        #[arg(long)] endpoint: String,
        /// Syslog facility (0-23). Default 16 (local0).
        #[arg(long)] facility: Option<u8>,
    },
    Disable,
    /// Send a test message end-to-end (verify your SIEM actually receives it).
    Test,
    /// Stream EVERY audit entry (not just security alerts) to SIEM live —
    /// see SyslogSender::set_stream_audit for throughput trade-offs.
    StreamAudit { #[arg(long)] on: bool },
}

#[derive(Subcommand)]
enum WormCommands {
    /// Set immutable flag (equivalent of `chattr +i`) — root only, and only
    /// clearable while no active hard retention is set (see `Retain`).
    Lock   { #[arg(long)] ino: u64 },
    /// Clear the immutable flag — fails if a retention period is still active.
    Unlock { #[arg(long)] ino: u64 },
    /// Set/extend a hard WORM retention (Unix epoch seconds) — can only
    /// ever be EXTENDED, never shortened, by anyone, including root.
    Retain { #[arg(long)] ino: u64, #[arg(long)] until: u64 },
    /// Show current WORM state for an inode.
    Show   { #[arg(long)] ino: u64 },
}

#[derive(Subcommand)]
enum IdsCommands {
    /// List recent alerts (most recent first).
    List { #[arg(short, long, default_value_t = 50)] count: usize },
    /// Lock a UID out completely — same effect as automatic lockout, but
    /// triggered manually (e.g. after reviewing an alert externally).
    Lock { #[arg(long)] uid: u32 },
    /// Clear an automatic (or manual) lockout for a UID.
    Unlock { #[arg(long)] uid: u32 },
    /// List currently locked-out UIDs.
    ListLocked,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Mount { device, mountpoint, key_file, passphrase, sealed_key_file, tpm_pcr, compression, noatime, allow_other, rate_limit_mb, strict } => {
            ghostfs::memlock::harden_process();
            let key = if let Some(sealed) = sealed_key_file {
                let blob = std::fs::read(&sealed)
                    .map_err(|e| format!("Cannot read sealed key blob {}: {}", sealed.display(), e))?;
                let seal = ghostfs::tpm::TpmSeal::new(tpm_pcr)?;
                let raw = seal.unseal_key(&blob)
                    .map_err(|e| format!(
                        "TPM unseal failed ({e}). This can mean the boot chain changed \
                         (BIOS/kernel/initramfs update moved PCR {tpm_pcr}) or the TPM is \
                         unavailable. Boot with 'ghostfs.recovery=1' to fall back to a \
                         passphrase prompt instead."
                    ))?;
                if raw.len() != 32 { return Err("Unsealed key is not 32 bytes — sealed blob corrupted".into()); }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&raw);
                arr
            } else {
                resolve_key(&device, key_file, passphrase)?
            };

            if strict {
                println!("→ --strict: verifying audit + forensics chains before mount...");
                let db = sled::open(&device)?;
                let mut audit = Audit::new(&db)?;
                audit.set_signing_key(&key);
                match audit.verify_signatures() {
                    Ok(n)  => println!("  ✓ audit log: {} signed blocks intact", n),
                    Err(e) => return Err(format!("STRICT MOUNT REFUSED — audit log tampered: {}", e).into()),
                }
                let forensics = Forensics::new(&db)?;
                match forensics.verify_chain() {
                    Ok(n)  => println!("  ✓ forensics chain: {} entries intact", n),
                    Err(e) => return Err(format!("STRICT MOUNT REFUSED — forensics chain broken: {}", e).into()),
                }
                drop(db);
            }

            let mut fs = GhostFS::new(&device, key, compression, noatime)?;

            if rate_limit_mb > 0 {
                fs.rate_limit = RateLimiter::with_rate(rate_limit_mb * 1024 * 1024);
            }

            let mut options = vec![
                MountOption::RW,
                MountOption::FSName("ghostfs".to_string()),
                MountOption::AutoUnmount,
            ];
            if allow_other { options.push(MountOption::AllowOther); }

            log::info!("GhostFS v0.3.0 mounting {} → {} [rate={}MiB/s]",
                device.display(), mountpoint.display(), rate_limit_mb);
            fuser::mount2(fs, &mountpoint, &options)?;
        }

        Commands::Mkfs { device, key_out, passphrase, interactive_passphrase, kdf_memory, kdf_iterations, block_size } => {
            let kdf_params = KdfParams::custom(kdf_memory, kdf_iterations, 4);

            let key: Key = if let Some(pass) = passphrase {
                println!("✓ Argon2id KDF (m={} KiB, t={})", kdf_memory, kdf_iterations);
                kdf::derive_key(&pass, &kdf_params)?.key
            } else if interactive_passphrase {
                let pass = kdf::read_passphrase_confirm("GhostFS passphrase: ")?;
                println!("✓ Argon2id KDF (m={} KiB, t={})", kdf_memory, kdf_iterations);
                kdf::derive_key(&pass, &kdf_params)?.key
            } else {
                rand::random()
            };

            // KDF params zapisywane do superblock — kluczowe dla round-trip mount
            ghostfs::format(&device, &key, kdf_params, block_size)?;

            if let Some(out) = key_out {
                if out.exists() { return Err(format!("{} exists — refusing overwrite", out.display()).into()); }
                std::fs::write(&out, hex::encode(key))?;
                #[cfg(unix)] {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600))?;
                }
                println!("✓ Master key → {}  ⚠ Keep safe.", out.display());
            }
            println!("✓ GhostFS v0.3.0 formatted at {}", device.display());
        }

        Commands::Umount { mountpoint } => {
            let s = std::process::Command::new("fusermount")
                .args(["-u", mountpoint.to_str().unwrap()]).status()?;
            if !s.success() { return Err(format!("fusermount -u failed: {}", s).into()); }
        }

        Commands::Audit { device, action } => {
            let db    = sled::open(&device)?;
            let mut audit = Audit::new(&db)?;
            match action {
                AuditCommands::Tail { count } => {
                    let entries = audit.tail(count)?;
                    for e in &entries {
                        let name = e.name.as_deref()
                            .map(|n| String::from_utf8_lossy(n).into_owned())
                            .unwrap_or_default();
                        println!("[ts={:>12}] seq={:>8} uid={:<6} op={:<12} ino={:<10} name={}",
                            e.timestamp, e.seq, e.uid, e.operation, e.ino, name);
                    }
                    println!("─ {} entries ─", entries.len());
                }
                AuditCommands::VerifySig { key_file, passphrase } => {
                    let key = resolve_key(&device, key_file, passphrase)?;
                    audit.set_signing_key(&key);
                    match audit.verify_signatures() {
                        Ok(n)  => println!("✓ {} audit block signatures verified — log intact", n),
                        Err(e) => { eprintln!("✗ AUDIT LOG TAMPERED: {}", e); std::process::exit(2); }
                    }
                }
            }
        }

        Commands::Quota { device, action } => {
            let db    = sled::open(&device)?;
            let quota = Quota::new(&db)?;
            match action {
                QuotaCommands::Set  { uid, limit } => { quota.set_limit(uid, limit)?; println!("✓ uid={} limit={}B", uid, limit); }
                QuotaCommands::Show { uid }        => {
                    let (used, limit) = quota.get_usage(uid)?;
                    if limit == 0 {
                        println!("uid={:<8} used={}B  limit=unlimited", uid, used);
                    } else {
                        let pct = (used as f64 / limit as f64) * 100.0;
                        println!("uid={:<8} used={}B  limit={}B  ({:.1}%)", uid, used, limit, pct);
                    }
                }
            }
        }

        Commands::Forensics { device, action } => {
            let db        = sled::open(&device)?;
            let forensics = Forensics::new(&db)?;
            match action {
                ForensicsCommands::Verify => {
                    match forensics.verify_chain() {
                        Ok(n)  => println!("✓ Chain intact (incl. WORM epoch seals) — {} entries", n),
                        Err(e) => { eprintln!("✗ CHAIN VIOLATION: {}", e); std::process::exit(2); }
                    }
                }
                ForensicsCommands::Tail { count } => {
                    let entries = forensics.tail(count)?;
                    for e in &entries {
                        let name = e.name.as_deref()
                            .map(|n| String::from_utf8_lossy(n).into_owned())
                            .unwrap_or_default();
                        println!("seq={:<8} ts={:<18} uid={:<6} op={:<12} ino={:<10} name={:<24} prev={} self={}",
                            e.seq, e.timestamp_us, e.uid, e.operation, e.ino, name,
                            hex::encode(&e.prev_hash[..4]), hex::encode(&e.self_hash[..4]));
                    }
                    println!("─ {} entries ─", entries.len());
                }
                ForensicsCommands::Export { output, key_file, passphrase } => {
                    let key    = resolve_key(&device, key_file, passphrase)?;
                    let sb     = Superblock::load_and_verify(&db, &key)?;
                    let crypto = Crypto::new_with_uuid(key, sb.data.volume_uuid)?;
                    let manifest = forensics.export_signed(&output, &crypto)?;
                    println!("✓ signed export → {} ({} entries)", output.display(), manifest.entry_count);
                    println!("  public key (share with auditor once, out-of-band): {}", manifest.public_key_hex);
                }
                ForensicsCommands::VerifyExport { input } => {
                    let (manifest, payload) = Forensics::read_signed_export(&input)?;
                    let ok = ghostfs::signing::verify_signed_export(&manifest, &payload)?;
                    println!("export:      {}", input.display());
                    println!("exported_at: {}", manifest.exported_at);
                    println!("entries:     {}", manifest.entry_count);
                    println!("public_key:  {}", manifest.public_key_hex);
                    if ok {
                        println!("RESULT: ✓ signature valid — export is authentic and unmodified.");
                    } else {
                        println!("RESULT: ✗ SIGNATURE INVALID — export is tampered, corrupted, or forged.");
                        std::process::exit(2);
                    }
                }
                ForensicsCommands::SigningKey { key_file, passphrase } => {
                    let key    = resolve_key(&device, key_file, passphrase)?;
                    let sb     = Superblock::load_and_verify(&db, &key)?;
                    let crypto = Crypto::new_with_uuid(key, sb.data.volume_uuid)?;
                    let signer = ghostfs::signing::ForensicsSigner::load_or_generate(&db, &crypto)?;
                    println!("{}", signer.public_key_hex());
                }
            }
        }

        Commands::Ids { device, action } => {
            let db = sled::open(&device)?;
            let ids = Ids::new(&db)?;
            let rate_limit = RateLimiter::new();
            let auto_response = ghostfs::response::AutoResponse::new(&db)?;

            match action {
                IdsCommands::List { count } => {
                    let alerts = ids.get_alerts(count)?;
                    for a in &alerts {
                        println!("[ts={:>12}] uid={:<6} ino={:<8} mask={:<3} reason={}",
                            a.timestamp, a.uid, a.ino, a.access_mask, a.reason);
                    }
                    println!("─ {} alerts ─", alerts.len());
                }
                IdsCommands::Lock { uid } => {
                    // Reuse AutoResponse's persistence so it survives remounts
                    // and is picked up consistently by GhostFS::new().
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                    db.insert(format!("ids:lockout:{}", uid).as_bytes(), bincode::serialize(&now)?)?;
                    println!("✓ uid={} locked out (manual)", uid);
                }
                IdsCommands::Unlock { uid } => {
                    auto_response.unlock_uid(&rate_limit, uid)?;
                    println!("✓ uid={} unlocked", uid);
                }
                IdsCommands::ListLocked => {
                    let locked = auto_response.list_locked()?;
                    for (uid, ts) in &locked {
                        println!("uid={:<8} locked_at={}", uid, ts);
                    }
                    println!("─ {} locked uid(s) ─", locked.len());
                }
            }
        }

        Commands::Mac { device, action } => {
            let db  = sled::open(&device)?;
            let mac = MacLabels::new(&db)?;
            match action {
                MacCommands::SetLabel { ino, level, compartments } => {
                    mac.set_label(ino, &MacLabel { level: level_from_u8(level)?, compartments })?;
                    println!("✓ label ino={}  level={}  comps=0x{:x}", ino, level, compartments);
                }
                MacCommands::SetClearance { uid, level, compartments, trusted } => {
                    mac.set_clearance(uid, &MacClearance { level: level_from_u8(level)?, compartments, trusted })?;
                    println!("✓ clearance uid={}  level={}  comps=0x{:x}  trusted={}", uid, level, compartments, trusted);
                }
                MacCommands::ShowLabel     { ino } => {
                    let l = mac.get_label(ino)?;
                    println!("ino={}  level={:?}  comps=0x{:x}", ino, l.level, l.compartments);
                }
                MacCommands::ShowClearance { uid } => {
                    let c = mac.get_clearance(uid)?;
                    println!("uid={}  level={:?}  comps=0x{:x}  trusted={}", uid, c.level, c.compartments, c.trusted);
                }
            }
        }

        Commands::Lockdown { device, action } => {
            let db = sled::open(&device)?;
            let auto_response = ghostfs::response::AutoResponse::new(&db)?;
            match action {
                LockdownCommands::Enable { reason } => {
                    auto_response.enable_global_lockdown(&reason)?;
                    println!("🔒 LOCKDOWN ENABLED — ALL access denied (including root) on every mount of this volume.");
                    println!("   Reason: {}", reason);
                    println!("   Clear with: ghostfs lockdown disable --device {}", device.display());
                }
                LockdownCommands::Disable => {
                    auto_response.disable_global_lockdown()?;
                    println!("✓ lockdown disabled — access restored");
                }
                LockdownCommands::Status => {
                    match auto_response.is_global_lockdown()? {
                        Some(reason) => println!("🔒 LOCKDOWN ACTIVE — reason: {}", reason),
                        None         => println!("✓ no active lockdown"),
                    }
                }
            }
        }

        Commands::Shamir { action } => {
            ghostfs::memlock::harden_process();
            match action {
                ShamirCommands::Split { key_file, shares, threshold, output_dir } => {
                    let hex_str = std::fs::read_to_string(&key_file)?;
                    let bytes = hex::decode(hex_str.trim())?;
                    if bytes.len() != 32 { return Err("Key file must contain a 32-byte hex key".into()); }
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&bytes);

                    let share_list = ghostfs::shamir::split(&secret, shares, threshold)?;
                    std::fs::create_dir_all(&output_dir)?;
                    println!("✓ split into {} shares, {} needed to reconstruct:", shares, threshold);
                    for s in &share_list {
                        let path = output_dir.join(format!("share-{}-of-{}.txt", s.index, shares));
                        std::fs::write(&path, s.serialize())?;
                        #[cfg(unix)] {
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                        }
                        println!("  {}", path.display());
                    }
                    println!(
                        "\nDistribute each share to a DIFFERENT custodian, over a DIFFERENT channel \
                         if possible. Any {} of these {} shares reconstruct the key; fewer than {} \
                         reveal mathematically ZERO information about it (information-theoretic \
                         security, not just 'hard to guess').", threshold, shares, threshold
                    );
                }
                ShamirCommands::Combine { share_files, output } => {
                    if output.exists() { return Err(format!("{} exists — refusing to overwrite", output.display()).into()); }
                    let mut share_list = Vec::new();
                    for f in &share_files {
                        let content = std::fs::read_to_string(f)
                            .map_err(|e| format!("Cannot read share file {}: {}", f.display(), e))?;
                        share_list.push(ghostfs::shamir::Share::deserialize(&content)?);
                    }
                    let secret = ghostfs::shamir::combine(&share_list)?;
                    std::fs::write(&output, hex::encode(secret))?;
                    #[cfg(unix)] {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
                    }
                    println!("✓ reconstructed key from {} share(s) → {}", share_files.len(), output.display());
                    println!("  Use with: ghostfs mount --key-file {} ...", output.display());
                }
            }
        }

        Commands::Ransomware { device, action } => {
            let db    = sled::open(&device)?;
            let ids   = Ids::new(&db)?;
            let guard = ghostfs::ransomware::RansomwareGuard::new(&db, &ids)?;
            match action {
                RansomwareCommands::Enable  => { guard.set_enabled(true)?;  println!("✓ ransomware detection enabled"); }
                RansomwareCommands::Disable => { guard.set_enabled(false)?; println!("✓ ransomware detection disabled — NOT recommended for production"); }
                RansomwareCommands::Allow    { uid } => { guard.allow_uid(uid)?;    println!("✓ uid={} exempted from ransomware detection", uid); }
                RansomwareCommands::Disallow { uid } => { guard.disallow_uid(uid)?; println!("✓ uid={} no longer exempted", uid); }
            }
        }

        Commands::Siem { device, action } => {
            let db     = sled::open(&device)?;
            let syslog = ghostfs::syslog::SyslogSender::new(&db)?;
            match action {
                SiemCommands::Configure { endpoint, facility } => {
                    syslog.configure(&endpoint, facility)?;
                    println!("✓ SIEM endpoint configured: {} (facility={})", endpoint, facility.unwrap_or(16));
                }
                SiemCommands::Disable => {
                    syslog.disable()?;
                    println!("✓ SIEM integration disabled");
                }
                SiemCommands::Test => {
                    syslog.send(
                        ghostfs::syslog::Severity::Notice, "TEST",
                        "GhostFS SIEM test message — if you see this, syslog delivery works.",
                    );
                    // send() jest fire-and-forget (osobny wątek) — dajemy mu
                    // chwilę, żeby faktycznie zdążył wysłać zanim proces CLI
                    // się zakończy i wątek zostanie ubity razem z nim.
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    println!("✓ test message sent (check your SIEM/syslog receiver)");
                }
                SiemCommands::StreamAudit { on } => {
                    syslog.set_stream_audit(on)?;
                    if on {
                        println!("✓ full audit streaming ENABLED — every logged operation now also goes to SIEM live.");
                        println!("  Not recommended for high-throughput workloads without a local rsyslog/syslog-ng relay.");
                    } else {
                        println!("✓ full audit streaming disabled (security alerts still stream regardless)");
                    }
                }
            }
        }

        Commands::Worm { device, action } => {
            let db   = sled::open(&device)?;
            let worm = ghostfs::worm::Worm::new(&db)?;
            // Operacje CLI działają bezpośrednio na DB (bez FUSE/uid z
            // requestu) — traktujemy je jako uprzywilejowane (root), tak
            // jak `ghostfs mac` / `ghostfs canary` już to robią. Kontrola
            // dostępu do samego wywołania `ghostfs worm ...` to
            // odpowiedzialność uprawnień pliku urządzenia / sudo.
            match action {
                WormCommands::Lock { ino } => {
                    worm.set_immutable(ino, true, true)?;
                    println!("✓ ino={} locked (immutable)", ino);
                }
                WormCommands::Unlock { ino } => {
                    worm.set_immutable(ino, false, true)?;
                    println!("✓ ino={} unlocked", ino);
                }
                WormCommands::Retain { ino, until } => {
                    worm.extend_retention(ino, until, true)?;
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                    println!("✓ ino={} retained until unix_ts={} ({}s from now)", ino, until, until.saturating_sub(now));
                }
                WormCommands::Show { ino } => {
                    let s = worm.get(ino)?;
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                    println!("ino={}  immutable={}  retain_until={} ({})",
                        ino, s.immutable, s.retention_until,
                        if s.retention_until > now { format!("ACTIVE, {}s remaining", s.retention_until - now) }
                        else if s.retention_until == 0 { "no hard retention".to_string() }
                        else { "expired".to_string() });
                }
            }
        }

        Commands::Canary { device, action } => {
            let db  = sled::open(&device)?;
            let ids = Ids::new(&db)?;
            let canary = Canary::new(&db, &ids)?;
            match action {
                CanaryCommands::Mark { ino, description, beacon_url } => {
                    canary.mark(ino, CanaryConfig { beacon_url, description: description.clone() })?;
                    println!("✓ ino={} marked as canary ('{}')", ino, description);
                }
                CanaryCommands::Unmark { ino } => {
                    canary.unmark(ino)?;
                    println!("✓ ino={} canary mark removed", ino);
                }
                CanaryCommands::List => {
                    let list = canary.list_canaries()?;
                    for (ino, cfg) in &list {
                        println!("ino={:<10} desc='{}'  beacon={}", ino, cfg.description,
                            cfg.beacon_url.as_deref().unwrap_or("-"));
                    }
                    println!("─ {} canaries ─", list.len());
                }
            }
        }

        Commands::Backup { device, output, key_file, passphrase, backup_passphrase, since_seq, changed_inodes } => {
            let master_key = resolve_key(&device, key_file, passphrase)?;
            let db = sled::open(&device)?;

            // volume_uuid + block_size — czytamy z superblocka (verify z master_key
            // po drodze potwierdza, że podane hasło/klucz faktycznie pasuje do wolumenu).
            let sb = Superblock::load_and_verify(&db, &master_key)?;
            // NOTE: `volume_uuid` used for block AAD binding lives only in the
            // in-memory `Crypto` struct (regenerated per-mount, not persisted
            // in the superblock) — see backup.rs module doc / README caveat.
            // For the backup MANIFEST we only need a stable *identifier*, not
            // the live AAD uuid (backup copies ciphertext 1:1, it never
            // re-derives AAD), so we derive one deterministically from the
            // superblock bytes — stable across mounts, good enough to tell
            // "is this backup from the volume I think it is" at a glance.
            let manifest_uuid = stable_volume_id(&sb);

            let crypto = ghostfs::crypto::Crypto::new(master_key)?;
            let (transport_key, custom, backup_kdf) = match &backup_passphrase {
                Some(pass) => {
                    let params = KdfParams::default();
                    let key = kdf::derive_key(pass, &params)?.key;
                    (key, true, Some(params))
                }
                None => (crypto.wrapping_key(), false, None),
            };

            let header = if let Some(seq) = since_seq {
                if changed_inodes.is_empty() {
                    return Err("--since-seq requires --changed-inodes <ino,ino,...> \
                                (list inodes touched since that seq — see 'ghostfs forensics tail')".into());
                }
                println!("→ Incremental backup since seq={} ({} inode(s))...", seq, changed_inodes.len());
                Backup::export_incremental(
                    &db, manifest_uuid, sb.data.block_size,
                    &transport_key, custom, backup_kdf, &output, seq, &changed_inodes,
                )?
            } else {
                println!("→ Full backup of {}...", device.display());
                Backup::export_full(
                    &db, manifest_uuid, sb.data.block_size,
                    &transport_key, custom, backup_kdf, &output,
                )?
            };

            println!("✓ {} entries → {}", header.entry_count, output.display());
            if custom {
                println!("  Encrypted with a SEPARATE backup passphrase (not the volume key).");
            } else {
                println!("  Encrypted with the volume's wrapping key — restore needs the same \
                           key-file/passphrase as the source volume (or its saved KDF params, \
                           embedded in this backup file).");
            }
        }

        Commands::Restore { input, device, key_file, passphrase, backup_passphrase } => {
            let header = Backup::read_header(&input)?;
            println!("Backup: created={} entries={} version={} incremental={}",
                header.created_at, header.entry_count, header.ghostfs_version,
                header.incremental_since_seq.map(|s| s.to_string()).unwrap_or_else(|| "no".into()));

            let transport_key = if header.custom_passphrase {
                let params = header.backup_kdf_params.clone()
                    .ok_or("Backup marked custom_passphrase=true but has no embedded KDF params — corrupted header")?;
                let pass = match backup_passphrase {
                    Some(p) => p,
                    None    => kdf::read_passphrase("Backup passphrase: ")?,
                };
                kdf::derive_key(&pass, &params)?.key
            } else {
                // Domyślny tryb: transport_key = wrapping_key(master_key).
                // master_key odtwarzamy z --key-file LUB z --passphrase +
                // source_kdf_params zapisanych w nagłówku backupu (działa
                // nawet gdy oryginalny wolumin/device już nie istnieje).
                let master_key: Key = if let Some(kf) = key_file {
                    let hex_str = std::fs::read_to_string(&kf)?;
                    let bytes = hex::decode(hex_str.trim())?;
                    if bytes.len() != 32 { return Err("Key must be 32 bytes".into()); }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                } else {
                    let params = header.source_kdf_params.clone()
                        .ok_or("Backup has no embedded source KDF params — provide --key-file instead of --passphrase")?;
                    let pass = match passphrase {
                        Some(p) => p,
                        None    => kdf::read_passphrase("Original volume passphrase: ")?,
                    };
                    kdf::derive_key(&pass, &params)?.key
                };
                let crypto = ghostfs::crypto::Crypto::new(master_key)?;
                crypto.wrapping_key()
            };

            println!("→ Restoring into new volume at {}...", device.display());
            let n = Backup::import(&input, &device, &transport_key)?;
            println!("✓ Imported {} entries → {}", n, device.display());
            println!("  NOTE: block-level data is still encrypted under the ORIGINAL master key —");
            println!("  mount the restored volume with the SAME key-file/passphrase you used on the source.");
        }

        Commands::TpmSealKey { key_file, output, pcr } => {
            ghostfs::memlock::harden_process();
            if output.exists() { return Err(format!("{} exists — refusing to overwrite", output.display()).into()); }
            let hex_str = std::fs::read_to_string(&key_file)?;
            let bytes = hex::decode(hex_str.trim())?;
            if bytes.len() != 32 { return Err("Key file must contain a 32-byte hex key".into()); }

            let seal = ghostfs::tpm::TpmSeal::new(pcr)?;
            let blob = seal.seal_key(&bytes)?;
            std::fs::write(&output, &blob)?;
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
            }
            if ghostfs::tpm::TpmSeal::is_hardware_available() {
                println!("✓ Key sealed to TPM (PCR {}) → {}", pcr, output.display());
            } else {
                println!("⚠ No TPM present — key sealed in SOFTWARE-ONLY mode (NO hardware");
                println!("  protection, dev/test only) → {}", output.display());
            }
            println!("  Use with: ghostfs mount --sealed-key-file {} --tpm-pcr {} ...", output.display(), pcr);
        }

        Commands::BackupInfo { input } => {
            let header = Backup::read_header(&input)?;
            println!("GhostFS backup: {}", input.display());
            println!("  version:            {}", header.ghostfs_version);
            println!("  created_at:         {}", header.created_at);
            println!("  volume_uuid:        {}", hex::encode(header.volume_uuid));
            println!("  block_size:         {}", header.block_size);
            println!("  entries:            {}", header.entry_count);
            println!("  incremental_since:  {}", header.incremental_since_seq.map(|s| s.to_string()).unwrap_or_else(|| "no (full backup)".into()));
            println!("  custom_passphrase:  {}", header.custom_passphrase);
        }

        Commands::Verify { device, key_file, passphrase, quick } => {
            println!("═══ GhostFS security self-test: {} ═══", device.display());
            let key = resolve_key(&device, key_file, passphrase)?;
            let db = sled::open(&device)?;
            let mut all_ok = true;

            // 1. Superblock HMAC — proves the key is correct AND the
            //    superblock (kdf params, volume_uuid, flags) is untampered.
            let mut volume_uuid: Option<[u8; 16]> = None;
            match Superblock::load_and_verify(&db, &key) {
                Ok(sb) => {
                    println!("[✓] superblock HMAC valid — version={} block_size={} volume_uuid={}",
                        sb.data.version, sb.data.block_size, hex::encode(sb.data.volume_uuid));
                    volume_uuid = Some(sb.data.volume_uuid);
                }
                Err(e) => { println!("[✗] SUPERBLOCK TAMPERED OR WRONG KEY: {}", e); all_ok = false; }
            }

            // 2. Audit log HMAC chain — detects retroactive edits/deletions
            //    of the access log (each block is HMAC-signed with the
            //    volume key at write time).
            let mut audit = Audit::new(&db)?;
            audit.set_signing_key(&key);
            match audit.verify_signatures() {
                Ok(n)  => println!("[✓] audit log intact — {} signed blocks", n),
                Err(e) => { println!("[✗] AUDIT LOG TAMPERED: {}", e); all_ok = false; }
            }

            // 3. Forensics chain-of-custody — hash-chained (like a mini
            //    blockchain) log of every access; a single deleted/edited
            //    entry breaks every hash after it, which is the point.
            let forensics = Forensics::new(&db)?;
            match forensics.verify_chain() {
                Ok(n)  => println!("[✓] forensics chain intact — {} entries (incl. WORM epoch seals)", n),
                Err(e) => { println!("[✗] FORENSICS CHAIN BROKEN: {}", e); all_ok = false; }
            }

            // 4. IDS alert summary — not a pass/fail check, but surfaced
            //    here because "the crypto checks out" and "nobody has been
            //    probing this volume" are two different questions.
            let ids = Ids::new(&db)?;
            match ids.get_alerts(5) {
                Ok(alerts) if !alerts.is_empty() => {
                    println!("[!] {} recent IDS alert(s) — run 'ghostfs ids --device {} ' for details",
                        alerts.len(), device.display());
                }
                Ok(_) => println!("[✓] no recent IDS alerts"),
                Err(e) => println!("[?] could not read IDS alerts: {}", e),
            }

            // 5. Full block-level integrity scan (blake3 leaves vs stored
            //    ciphertext, dedup refcount consistency) — the expensive
            //    check, skippable with --quick on large volumes.
            if quick {
                println!("[·] skipping block-level integrity scan (--quick)");
            } else if let Some(uuid) = volume_uuid {
                println!("→ running full block-level integrity scan (this can take a while)...");
                let crypto      = Crypto::new_with_uuid(key, uuid)?;
                // Kompresja jest self-describing (magic header w każdym
                // bloku — patrz data/compression.rs), więc typ podany tu
                // przy konstrukcji nie ma znaczenia dla decompress().
                let compression = Compression::new(CompressionType::None);
                let dedup       = Deduplication::new(&db)?;
                let versioning  = Versioning::new(&db)?;
                let repair      = Repair::new(&db, &Some(crypto), &compression, &dedup, &versioning)?;
                let (scanned, repaired) = repair.scan_report()?;
                if repaired == 0 {
                    println!("[✓] integrity scan: {} inodes scanned, 0 corrupted", scanned);
                } else {
                    println!("[!] integrity scan: {} inodes scanned, {} corrupted (auto-restored from \
                              last known-good version where possible — check logs for any that couldn't be)",
                              scanned, repaired);
                    all_ok = false;
                }
            } else {
                println!("[·] skipping block-level integrity scan — no verified volume_uuid to decrypt with \
                          (superblock check above failed)");
            }

            println!("═══════════════════════════════════════════════");
            if all_ok {
                println!("RESULT: OK — no tampering detected.");
            } else {
                println!("RESULT: ISSUES FOUND — see [✗]/[!] lines above.");
                std::process::exit(2);
            }
        }

        Commands::Keygen { output } => {
            ghostfs::memlock::harden_process();
            if output.exists() { return Err(format!("{} exists — refusing overwrite", output.display()).into()); }
            let key: [u8; 32] = rand::random();
            std::fs::write(&output, hex::encode(key))?;
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
            }
            println!("✓ Key → {}  ⚠ Keep safe.", output.display());
        }
    }

    Ok(())
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn resolve_key(
    device:     &std::path::Path,
    key_file:   Option<PathBuf>,
    passphrase: Option<String>,
) -> Result<Key, Box<dyn std::error::Error>> {
    if let Some(kf) = key_file {
        let hex_str = std::fs::read_to_string(&kf)
            .map_err(|e| format!("Cannot read key file {}: {}", kf.display(), e))?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| format!("Invalid hex in key file: {}", e))?;
        if bytes.len() != 32 { return Err(format!("Key must be 32 bytes (got {})", bytes.len()).into()); }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(arr);
    }

    let db = sled::open(device)?;
    let kdf_params = Superblock::load_kdf_params(&db).unwrap_or_default();
    drop(db);

    let pass = if let Some(p) = passphrase { p }
    else { kdf::read_passphrase("GhostFS passphrase: ")? };

    Ok(kdf::derive_key(&pass, &kdf_params)?.key)
}

/// Deterministyczny, stabilny (nie zmienia się między mountami) identyfikator
/// wolumenu do celów samego manifestu backupu — patrz komentarz przy `Commands::Backup`.
fn stable_volume_id(sb: &Superblock) -> [u8; 16] {
    let bytes = bincode::serialize(&sb.data).unwrap_or_default();
    let hash = blake3::hash(&bytes);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash.as_bytes()[..16]);
    id
}

fn level_from_u8(level: u8) -> Result<SensitivityLevel, Box<dyn std::error::Error>> {
    SensitivityLevel::from_u8(level)
        .ok_or_else(|| format!("Invalid level {}; must be 0..3", level).into())
}
