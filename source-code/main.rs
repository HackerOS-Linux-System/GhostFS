use clap::{Parser, Subcommand};
use hex;
use ghostfs::GhostFS;
use std::path::PathBuf;
use fuser::MountOption;

#[derive(Parser)]
#[command(
name    = "ghostfs",
version = "0.4.0",
about   = "GhostFS — production-grade filesystem for HackerOS",
long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount a GhostFS volume
    Mount {
        /// Path to the sled database directory or image file
        #[arg(short, long)]
        device: PathBuf,

        /// FUSE mountpoint
        #[arg(short, long)]
        mountpoint: PathBuf,

        /// Enable encryption (mandatory in cybersec build)
        #[cfg(feature = "normal")]
        #[arg(long, default_value_t = false)]
        cybersecurity: bool,

        /// Always true in cybersec build
        #[cfg(feature = "cybersec")]
        #[arg(long, default_value_t = true)]
        cybersecurity: bool,

        /// Path to a file containing a 32-byte hex-encoded AES-256 key
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Compression algorithm: none | zlib | zstd | lz4
        #[arg(long)]
        compression: Option<String>,

        /// Disable access-time updates (recommended for performance)
        #[arg(long)]
        noatime: bool,

        /// Allow other users to access the mountpoint
        #[arg(long)]
        allow_other: bool,
    },

    /// Format (initialise) a GhostFS volume
    Mkfs {
        /// Path to the sled database directory or image file
        #[arg(short, long)]
        device: PathBuf,

        /// Pre-format with encryption metadata hint
        #[arg(long)]
        encryption: bool,

        /// Block size in bytes (default: 4096)
        #[arg(long)]
        block_size: Option<u32>,
    },

    /// Unmount a GhostFS volume
    Umount {
        /// FUSE mountpoint to unmount
        #[arg(short, long)]
        mountpoint: PathBuf,
    },

    /// Inspect the audit log
    Audit {
        /// Path to the sled database
        #[arg(short, long)]
        device: PathBuf,

        #[command(subcommand)]
        action: AuditCommands,
    },

    /// Manage per-user disk quotas
    Quota {
        /// Path to the sled database
        #[arg(short, long)]
        device: PathBuf,

        #[command(subcommand)]
        action: QuotaCommands,
    },

    /// [cybersec] Verify / export the forensics chain
    #[cfg(feature = "cybersec")]
    Forensics {
        /// Path to the sled database
        #[arg(short, long)]
        device: PathBuf,

        #[command(subcommand)]
        action: ForensicsCommands,
    },

    /// [cybersec] View IDS alerts
    #[cfg(feature = "cybersec")]
    Ids {
        /// Path to the sled database
        #[arg(short, long)]
        device: PathBuf,

        /// Number of most-recent alerts to show (default: 50)
        #[arg(short, long, default_value_t = 50)]
        count: usize,
    },

    /// [cybersec] Manage MAC labels and clearances
    #[cfg(feature = "cybersec")]
    Mac {
        /// Path to the sled database
        #[arg(short, long)]
        device: PathBuf,

        #[command(subcommand)]
        action: MacCommands,
    },
}

// ── Audit subcommands ──────────────────────────────────────────────────────
#[derive(Subcommand)]
enum AuditCommands {
    /// Show the N most recent audit entries
    Tail {
        #[arg(short, long, default_value_t = 100)]
        count: usize,
    },
}

// ── Quota subcommands ──────────────────────────────────────────────────────
#[derive(Subcommand)]
enum QuotaCommands {
    /// Set a quota limit for a user (bytes)
    Set {
        #[arg(long)]
        uid: u32,
        /// Quota limit in bytes (0 = unlimited)
        #[arg(long)]
        limit: u64,
    },
    /// Show quota usage for a user
    Show {
        #[arg(long)]
        uid: u32,
    },
}

// ── Forensics subcommands ──────────────────────────────────────────────────
#[cfg(feature = "cybersec")]
#[derive(Subcommand)]
enum ForensicsCommands {
    /// Verify the entire hash chain
    Verify,
    /// Export the N most-recent entries as JSON-like text
    Tail {
        #[arg(short, long, default_value_t = 100)]
        count: usize,
    },
}

// ── MAC subcommands ────────────────────────────────────────────────────────
#[cfg(feature = "cybersec")]
#[derive(Subcommand)]
enum MacCommands {
    /// Set a MAC label on an inode
    SetLabel {
        #[arg(long)]
        ino: u64,
        /// Sensitivity level: 0=Unclassified 1=Restricted 2=Confidential 3=TopSecret
        #[arg(long)]
        level: u8,
        /// Compartment bitmask (hex, e.g. 0x3)
        #[arg(long, default_value_t = 0)]
        compartments: u64,
    },
    /// Set a MAC clearance for a UID
    SetClearance {
        #[arg(long)]
        uid: u32,
        /// Max clearance level: 0..3
        #[arg(long)]
        level: u8,
        /// Compartment bitmask
        #[arg(long, default_value_t = 0xFFFF_FFFF_FFFF_FFFF)]
        compartments: u64,
        /// Mark as trusted (bypass No-Write-Down)
        #[arg(long)]
        trusted: bool,
    },
    /// Show the MAC label for an inode
    ShowLabel {
        #[arg(long)]
        ino: u64,
    },
}

// ─────────────────────────────────────────────────────────────────────────
fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        // ── mount ──────────────────────────────────────────────────
        Commands::Mount {
            device,
            mountpoint,
            cybersecurity,
            key_file,
            compression,
            noatime,
            allow_other,
        } => {
            let key = resolve_key(cybersecurity, key_file)?;
            let fs = GhostFS::new(&device, cybersecurity, key, compression, noatime)?;

            let mut options = vec![
                MountOption::RW,
                MountOption::FSName("ghostfs".to_string()),
                MountOption::AutoUnmount,
            ];
            if allow_other {
                options.push(MountOption::AllowOther);
            }

            log::info!(
                "GhostFS mounting {} → {} [cybersec={}]",
                device.display(),
                       mountpoint.display(),
                       cybersecurity
            );
            fuser::mount2(fs, &mountpoint, &options)?;
        }

        // ── mkfs ───────────────────────────────────────────────────
        Commands::Mkfs { device, encryption, block_size } => {
            ghostfs::format(&device, encryption, block_size)?;
            println!("✓ GhostFS formatted at {}", device.display());
        }

        // ── umount ─────────────────────────────────────────────────
        Commands::Umount { mountpoint } => {
            std::process::Command::new("fusermount")
            .args(["-u", mountpoint.to_str().unwrap()])
            .status()?;
        }

        // ── audit ──────────────────────────────────────────────────
        Commands::Audit { device, action } => {
            let db = sled::open(&device)?;
            let audit = ghostfs::audit::Audit::new(&db)?;
            match action {
                AuditCommands::Tail { count } => {
                    let entries = audit.tail(count)?;
                    if entries.is_empty() {
                        println!("(no audit entries)");
                    }
                    for e in &entries {
                        let name = e.name.as_deref()
                        .map(|n| String::from_utf8_lossy(n).into_owned())
                        .unwrap_or_default();
                        println!(
                            "[{}] seq={:>8} uid={:<6} op={:<12} ino={:<10} name={}",
                            e.timestamp, e.seq, e.uid, e.operation, e.ino, name
                        );
                    }
                    println!("─ {} entries shown ─", entries.len());
                }
            }
        }

        // ── quota ──────────────────────────────────────────────────
        Commands::Quota { device, action } => {
            let db = sled::open(&device)?;
            let quota = ghostfs::quota::Quota::new(&db)?;
            match action {
                QuotaCommands::Set { uid, limit } => {
                    quota.set_limit(uid, limit)?;
                    println!("✓ Quota for uid {} set to {} bytes", uid, limit);
                }
                QuotaCommands::Show { uid } => {
                    quota.show(uid)?;
                }
            }
        }

        // ── forensics (cybersec only) ──────────────────────────────
        #[cfg(feature = "cybersec")]
        Commands::Forensics { device, action } => {
            let db = sled::open(&device)?;
            let forensics = ghostfs::forensics::Forensics::new(&db)?;
            match action {
                ForensicsCommands::Verify => {
                    match forensics.verify_chain() {
                        Ok(n) => println!("✓ Forensics chain intact — {} entries verified", n),
                        Err(e) => {
                            eprintln!("✗ CHAIN INTEGRITY VIOLATION: {}", e);
                            std::process::exit(2);
                        }
                    }
                }
                ForensicsCommands::Tail { count } => {
                    let entries = forensics.tail(count)?;
                    for e in &entries {
                        let name = e.name.as_deref()
                        .map(|n| String::from_utf8_lossy(n).into_owned())
                        .unwrap_or_default();
                        println!(
                            "seq={:<8} ts_us={} uid={:<6} op={:<12} ino={:<10} name={} prev={} self={}",
                            e.seq,
                            e.timestamp_us,
                            e.uid,
                            e.operation,
                            e.ino,
                            name,
                            hex::encode(&e.prev_hash[..4]),
                                 hex::encode(&e.self_hash[..4]),
                        );
                    }
                    println!("─ {} entries shown ─", entries.len());
                }
            }
        }

        // ── ids (cybersec only) ────────────────────────────────────
        #[cfg(feature = "cybersec")]
        Commands::Ids { device, count } => {
            let db = sled::open(&device)?;
            let ids = ghostfs::ids::Ids::new(&db)?;
            let alerts = ids.recent_alerts(count)?;
            if alerts.is_empty() {
                println!("(no IDS alerts)");
            }
            for a in &alerts {
                println!(
                    "[ts={}] uid={:<6} kind={:?}  {}",
                    a.timestamp, a.uid, a.kind, a.detail
                );
            }
            println!("─ {} alerts shown ─", alerts.len());
        }

        // ── mac (cybersec only) ────────────────────────────────────
        #[cfg(feature = "cybersec")]
        Commands::Mac { device, action } => {
            let db = sled::open(&device)?;
            let mac = ghostfs::mac::MacLabels::new(&db)?;
            match action {
                MacCommands::SetLabel { ino, level, compartments } => {
                    let sens = level_from_u8(level)?;
                    mac.set_label(ino, &ghostfs::mac::MacLabel {
                        level: sens,
                        compartments,
                    })?;
                    println!("✓ MAC label set on ino {} — level={} compartments=0x{:x}",
                             ino, level, compartments);
                }
                MacCommands::SetClearance { uid, level, compartments, trusted } => {
                    let sens = level_from_u8(level)?;
                    mac.set_clearance(uid, &ghostfs::mac::MacClearance {
                        level: sens,
                        compartments,
                        trusted,
                    })?;
                    println!("✓ Clearance set for uid {} — level={} compartments=0x{:x} trusted={}",
                             uid, level, compartments, trusted);
                }
                MacCommands::ShowLabel { ino } => {
                    let label = mac.get_label(ino)?;
                    println!("ino={} level={:?} compartments=0x{:x}",
                             ino, label.level, label.compartments);
                }
            }
        }
    }

    Ok(())
}

// ─── helpers ──────────────────────────────────────────────────────────────

fn resolve_key(
    cybersecurity: bool,
    key_file: Option<PathBuf>,
) -> Result<Option<ghostfs::crypto::Key>, Box<dyn std::error::Error>> {
    if !cybersecurity {
        return Ok(None);
    }
    let kf = key_file.ok_or("--key-file required when --cybersecurity is set")?;
    let key_hex = std::fs::read_to_string(&kf)
    .map_err(|e| format!("Cannot read key file {}: {}", kf.display(), e))?;
    let key_bytes = hex::decode(key_hex.trim())
    .map_err(|e| format!("Invalid hex in key file: {}", e))?;
    if key_bytes.len() != 32 {
        return Err(format!("Key must be exactly 32 bytes (got {})", key_bytes.len()).into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    Ok(Some(arr))
}

#[cfg(feature = "cybersec")]
fn level_from_u8(level: u8) -> Result<ghostfs::mac::SensitivityLevel, Box<dyn std::error::Error>> {
    use ghostfs::mac::SensitivityLevel;
    match level {
        0 => Ok(SensitivityLevel::Unclassified),
        1 => Ok(SensitivityLevel::Restricted),
        2 => Ok(SensitivityLevel::Confidential),
        3 => Ok(SensitivityLevel::TopSecret),
        _ => Err(format!("Invalid sensitivity level {}; must be 0..3", level).into()),
    }
}
