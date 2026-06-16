use rand;
use sled;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use fuser::MountOption;
use hex;

use ghostfs::{
    GhostFS,
    crypto::Key,
    audit::Audit,
    quota::Quota,
    forensics::Forensics,
    ids::Ids,
    mac::{MacLabels, MacLabel, MacClearance, SensitivityLevel},
    canary::{Canary, CanaryConfig},
    kdf::{self, KdfParams},
    superblock::Superblock,
    rate_limit::RateLimiter,
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
        #[arg(long, conflicts_with = "passphrase")] key_file:   Option<PathBuf>,
        #[arg(long, conflicts_with = "key_file")]   passphrase: Option<String>,
        #[arg(long)] compression:   Option<String>,
        #[arg(long)] noatime:       bool,
        #[arg(long)] allow_other:   bool,
        #[arg(long, default_value_t = 100)] rate_limit_mb: u64,
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
        #[arg(short, long, default_value_t = 50)] count: usize,
    },

    Mac {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: MacCommands,
    },

    /// Manage canary (honeypot) files
    Canary {
        #[arg(short, long)] device: PathBuf,
        #[command(subcommand)] action: CanaryCommands,
    },

    Keygen { #[arg(short, long)] output: PathBuf },
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Mount { device, mountpoint, key_file, passphrase, compression, noatime, allow_other, rate_limit_mb } => {
            let key = resolve_key(&device, key_file, passphrase)?;
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
                QuotaCommands::Show { uid }        => { quota.show(uid)?; }
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
            }
        }

        Commands::Ids { device, count } => {
            let db     = sled::open(&device)?;
            let ids    = Ids::new(&db)?;
            let alerts = ids.recent_alerts(count)?;
            for a in &alerts {
                println!("[ts={:>12}] uid={:<6} kind={:?}  detail={}", a.timestamp, a.uid, a.kind, a.detail);
            }
            println!("─ {} alerts ─", alerts.len());
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

        Commands::Keygen { output } => {
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

fn level_from_u8(level: u8) -> Result<SensitivityLevel, Box<dyn std::error::Error>> {
    SensitivityLevel::from_u8(level)
        .ok_or_else(|| format!("Invalid level {}; must be 0..3", level).into())
}
