use clap::{Parser, Subcommand};
use hfs::HFS;
use std::path::PathBuf;
use fuser::MountOption;

#[derive(Parser)]
#[command(name = "hfs")]
#[command(about = "HackerOS File System", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount an HFS filesystem
    Mount {
        #[arg(short, long)]
        device: PathBuf,   // ścieżka do bazy danych sled

        #[arg(short, long)]
        mountpoint: PathBuf,

        #[arg(long)]
        cybersecurity: bool,

        #[arg(long)]
        key_file: Option<PathBuf>,

        #[arg(long)]
        compression: Option<String>,  // "zlib", "none"

        #[arg(long)]
        noatime: bool,
    },

    /// Create a new HFS filesystem
    Mkfs {
        #[arg(short, long)]
        device: PathBuf,

        #[arg(long)]
        encryption: bool,

        #[arg(long)]
        block_size: Option<u32>,
    },

    /// Unmount an HFS filesystem
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

            let fs = HFS::new(&device, cybersecurity, key, compression, noatime)?;
            let options = vec![
                MountOption::RW,
                MountOption::FSName("hfs".to_string()),
                MountOption::AutoUnmount,
            ];
            fuser::mount2(fs, &mountpoint, &options)?;
        }
        Commands::Mkfs { device, encryption, block_size } => {
            hfs::format(&device, encryption, block_size)?;
        }
        Commands::Umount { mountpoint } => {
            // Użyj fusermount -u
            std::process::Command::new("fusermount")
                .args(&["-u", mountpoint.to_str().unwrap()])
                .status()?;
        }
    }

    Ok(())
                              }
