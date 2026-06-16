#![allow(dead_code)]

use tokio::sync::broadcast;
use serde::{Serialize, Deserialize};

/// Event wysyłany do SIEM przez gRPC stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForensicsEvent {
    pub seq:          u64,
    pub timestamp_us: u128,
    pub uid:          u32,
    pub operation:    String,
    pub ino:          u64,
    pub name:         String,
    pub prev_hash:    String,
    pub self_hash:    String,
}

pub type EventSender   = broadcast::Sender<ForensicsEvent>;
pub type EventReceiver = broadcast::Receiver<ForensicsEvent>;

/// Tworzy parę (sender, receiver) dla gRPC streaming.
pub fn create_event_channel(capacity: usize) -> (EventSender, EventReceiver) {
    broadcast::channel(capacity)
}

/// Struktury proto3-kompatybilne (prost::Message) — do wykorzystania
/// po wygenerowaniu kodu serwisu z proto/forensics.proto via tonic-build.
pub mod proto {
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    pub struct ForensicsEventProto {
        #[prost(uint64, tag = "1")] pub seq:          u64,
        #[prost(uint64, tag = "2")] pub timestamp_us: u64,
        #[prost(uint32, tag = "3")] pub uid:          u32,
        #[prost(string, tag = "4")] pub operation:    String,
        #[prost(uint64, tag = "5")] pub ino:          u64,
        #[prost(string, tag = "6")] pub name:         String,
        #[prost(string, tag = "7")] pub prev_hash:    String,
        #[prost(string, tag = "8")] pub self_hash:    String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct SubscribeRequest {
        /// Zacznij od tego seq (0 = bieżące)
        #[prost(uint64, tag = "1")] pub from_seq: u64,
    }
}

/// Konfiguracja serwera gRPC.
#[derive(Clone, Debug)]
pub struct GrpcForensicsConfig {
    pub endpoint:  String,
    pub cert_path: Option<String>,
    pub key_path:  Option<String>,
}

impl From<ForensicsEvent> for proto::ForensicsEventProto {
    fn from(e: ForensicsEvent) -> Self {
        proto::ForensicsEventProto {
            seq:          e.seq,
            timestamp_us: e.timestamp_us as u64,
            uid:          e.uid,
            operation:    e.operation,
            ino:          e.ino,
            name:         e.name,
            prev_hash:    e.prev_hash,
            self_hash:    e.self_hash,
        }
    }
}

/// Streamer — wywołać emit() z Forensics::record() po każdej operacji FS.
/// Subskrybenci (gRPC handlery) czytają z EventReceiver.
pub struct ForensicsStreamer {
    sender: EventSender,
}

impl ForensicsStreamer {
    pub fn new(capacity: usize) -> (Self, EventReceiver) {
        let (tx, rx) = create_event_channel(capacity);
        (Self { sender: tx }, rx)
    }

    /// Emit event do wszystkich podłączonych klientów SIEM.
    /// Brak subskrybentów = Err (ignorowany — to nie jest błąd FS).
    pub fn emit(&self, event: ForensicsEvent) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> EventReceiver {
        self.sender.subscribe()
    }
}

/// Minimalny serwer TCP nasłuchujący na endpoint — placeholder dla pełnego
/// tonic::Server z TLS (cert_path/key_path z config) i wygenerowanym proto service.
pub async fn run_grpc_server(
    config: GrpcForensicsConfig,
    mut receiver: EventReceiver,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: std::net::SocketAddr = config.endpoint.parse()?;
    log::info!("GhostFS gRPC forensics: listening on {} (tls_cert={:?})", addr, config.cert_path);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    log::info!("GhostFS gRPC forensics: ready");

    loop {
        tokio::select! {
            // Drain events to keep the channel from filling up when idle
            ev = receiver.recv() => {
                if let Ok(event) = ev {
                    log::debug!("forensics event: seq={} op={}", event.seq, event.operation);
                }
            }
            conn = listener.accept() => {
                if let Ok((_socket, peer)) = conn {
                    log::info!("gRPC forensics: connection from {}", peer);
                    // Pełna implementacja: handshake TLS + proto service handler
                }
            }
        }
    }
}
