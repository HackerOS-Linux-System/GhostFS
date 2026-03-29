use clap::{Parser, Subcommand};
use ghostfs::GhostFS;          // ← poprawny import – nazwa crate'a małymi literami
use std::path::PathBuf;
use fuser::MountOption;

#[derive(Parser)]
#[command(name = "ghostfs")]
#[command(about = "GhostFS - File System for HackerOS", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Mount {
        #[arg(short, long)]
        device: PathBuf,
        #[arg(short, long)]
        mountpoint: PathBuf,
        #[cfg(feature = "cybersec")]
        #[arg(long, default_value_t = true)]
        cybersecurity: bool,
        #[cfg(feature = "normal")]
        #[arg(long)]
        cybersecurity: bool,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        compression: Option<String>,
        #[arg(long)]
        noatime: bool,
    },
    Mkfs {
        #[arg(short, long)]
        device: PathBuf,
        #[arg(long)]
        encryption: bool,
        #[arg(long)]
        block_size: Option<u32>,
    },
    Umount {
        #[arg(short, long)]
        mountpoint: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Mount { device, mountpoint, cybersecurity, key_file, compression, noatime } => {
            #[cfg(feature = "cybersec")]
            let key = {
                if let Some(kf) = key_file {
                    let key_hex = std::fs::read_to_string(kf)?;
                    let key_bytes = hex::decode(key_hex.trim())?;
                    if key_bytes.len() != 32 {
                        eprintln!("Key must be 32 bytes");
                        std::process::exit(1);
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&key_bytes);
                    Some(arr)
                } else {
                    eprintln!("Key file required for cybersecurity mode");
                    std::process::exit(1);
                }
            };

            #[cfg(feature = "normal")]
            let key = if cybersecurity {
                if let Some(kf) = key_file {
                    let key_hex = std::fs::read_to_string(kf)?;
                    let key_bytes = hex::decode(key_hex.trim())?;
                    if key_bytes.len() != 32 {
                        eprintln!("Key must be 32 bytes");
                        std::process::exit(1);
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&key_bytes);
                    Some(arr)
                } else {
                    eprintln!("Key file required for cybersecurity mode");
                    std::process::exit(1);
                }
            } else {
                None
            };

            let fs = GhostFS::new(&device, cybersecurity, key, compression, noatime)?;
            let options = vec![
                MountOption::RW,
                MountOption::FSName("ghostfs".to_string()),
                MountOption::AutoUnmount,
            ];
            fuser::mount2(fs, &mountpoint, &options)?;
        }
        Commands::Mkfs { device, encryption, block_size } => {
            ghostfs::format(&device, encryption, block_size)?;   // ← poprawna ścieżka do funkcji format
        }
        Commands::Umount { mountpoint } => {
            std::process::Command::new("fusermount")
            .args(&["-u", mountpoint.to_str().unwrap()])
            .status()?;
        }
    }
    Ok(())
}
