#![allow(dead_code)]

use tokio::sync::broadcast;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use crate::error::HfsError;

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

pub fn create_event_channel(capacity: usize) -> (EventSender, EventReceiver) {
    broadcast::channel(capacity)
}

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
        #[prost(uint64, tag = "1")] pub from_seq: u64,
    }
}

impl From<ForensicsEvent> for proto::ForensicsEventProto {
    fn from(e: ForensicsEvent) -> Self {
        proto::ForensicsEventProto {
            seq: e.seq, timestamp_us: e.timestamp_us as u64,
            uid: e.uid, operation: e.operation, ino: e.ino,
            name: e.name, prev_hash: e.prev_hash, self_hash: e.self_hash,
        }
    }
}

#[derive(Clone, Debug)]
pub struct GrpcForensicsConfig {
    pub endpoint:       String,
    /// PEM cert dla TLS — obowiązkowe w trybie produkcyjnym.
    pub cert_path:      Option<String>,
    pub key_path:       Option<String>,
    /// PEM CA cert dla mutual TLS (client auth) — Red Team: tylko zaufane SIEM.
    pub ca_cert_path:   Option<String>,
    /// Klucz HMAC do uwierzytelniania eventów (niezależnie od TLS).
    pub hmac_key_hex:   Option<String>,
}

impl GrpcForensicsConfig {
    pub fn is_tls_configured(&self) -> bool {
        self.cert_path.is_some() && self.key_path.is_some()
    }
}

/// Streamer — centralny emiter eventów forensics.
/// Podłączony do `Forensics::record()` przez `GhostFS` struct.
#[derive(Clone)]
pub struct ForensicsStreamer {
    sender:   EventSender,
    hmac_key: Option<[u8; 32]>,
}

impl ForensicsStreamer {
    pub fn new(capacity: usize, hmac_key_hex: Option<&str>) -> (Self, EventReceiver) {
        let (tx, rx) = create_event_channel(capacity);
        let hmac_key = hmac_key_hex.and_then(|h| {
            hex::decode(h).ok().and_then(|b| {
                if b.len() == 32 { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); Some(arr) }
                else { None }
            })
        });
        (Self { sender: tx, hmac_key }, rx)
    }

    /// Emituj event z opcjonalnym HMAC podpisem.
    pub fn emit(&self, mut event: ForensicsEvent) {
        if let Some(key) = &self.hmac_key {
            // Podpisz event: HMAC(key, seq||uid||op||ino) dołącz do self_hash.
            let mut h = blake3::Hasher::new_keyed(key);
            h.update(&event.seq.to_le_bytes());
            h.update(&event.uid.to_le_bytes());
            h.update(event.operation.as_bytes());
            h.update(&event.ino.to_le_bytes());
            let mac = hex::encode(h.finalize().as_bytes());
            // Dołącz MAC do self_hash (format: "<chain_hash>|<mac>")
            event.self_hash = format!("{}|{}", event.self_hash, mac);
        }
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> EventReceiver { self.sender.subscribe() }
    pub fn receiver_count(&self) -> usize    { self.sender.receiver_count() }
}

/// Serwer TCP/TLS nasłuchujący na endpoint i streamujący eventy.
/// Używa tokio_rustls dla TLS — wymagane cert + key w konfiguracji.
pub async fn run_grpc_server(
    config:   GrpcForensicsConfig,
    streamer: Arc<ForensicsStreamer>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: std::net::SocketAddr = config.endpoint.parse()?;

    if !config.is_tls_configured() {
        log::error!(
            "GhostFS gRPC forensics: TLS cert/key not configured — refusing to start plaintext server. \
             Set cert_path and key_path in GrpcForensicsConfig."
        );
        return Err("TLS required for gRPC forensics server".into());
    }

    log::info!(
        "GhostFS gRPC forensics: starting TLS server on {} (cert={:?}, mtls_ca={:?})",
        addr, config.cert_path, config.ca_cert_path
    );

    #[cfg(feature = "grpc-tls")]
    {
        use tokio_rustls::TlsAcceptor;
        use rustls::{ServerConfig, Certificate, PrivateKey};
        use std::fs;

        let cert_pem = fs::read(config.cert_path.as_ref().unwrap())?;
        let key_pem  = fs::read(config.key_path.as_ref().unwrap())?;
        let certs    = rustls_pemfile::certs(&mut cert_pem.as_ref())
            .map(|r| r.map(|c| Certificate(c.to_vec())))?
            .collect::<Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_ref())?
            .map(|k| PrivateKey(k.secret_der().to_vec()))
            .ok_or("No private key found")?;

        let mut tls_config = ServerConfig::builder()
            .with_safe_defaults();

        // mTLS: jeśli podano CA cert, wymagaj client auth.
        let tls_config = if let Some(ca_path) = &config.ca_cert_path {
            let ca_pem  = fs::read(ca_path)?;
            let mut store = rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut ca_pem.as_ref()) {
                store.add(&rustls::Certificate(cert?.to_vec()))?;
            }
            tls_config
                .with_client_cert_verifier(Arc::new(
                    rustls::server::AllowAnyAuthenticatedClient::new(store)
                ))
                .with_single_cert(certs, key)?
        } else {
            tls_config.with_no_client_auth().with_single_cert(certs, key)?
        };

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        log::info!("GhostFS gRPC forensics: TLS ready on {}", addr);

        loop {
            let (tcp, peer) = listener.accept().await?;
            let acceptor    = acceptor.clone();
            let streamer    = streamer.clone();

            tokio::spawn(async move {
                match acceptor.accept(tcp).await {
                    Ok(tls_stream) => {
                        log::info!("gRPC forensics TLS: client connected from {}", peer);
                        let mut rx = streamer.subscribe();
                        // Stream events jako JSON newline-delimited over TLS.
                        use tokio::io::AsyncWriteExt;
                        let (_, mut writer) = tokio::io::split(tls_stream);
                        while let Ok(event) = rx.recv().await {
                            if let Ok(json) = serde_json::to_string(&event) {
                                let line = format!("{}\n", json);
                                if writer.write_all(line.as_bytes()).await.is_err() { break; }
                            }
                        }
                        log::info!("gRPC forensics: client {} disconnected", peer);
                    }
                    Err(e) => log::warn!("gRPC forensics TLS handshake failed from {}: {}", peer, e),
                }
            });
        }
    }

    #[cfg(not(feature = "grpc-tls"))]
    {
        log::warn!(
            "GhostFS gRPC forensics: compiled without 'grpc-tls' feature. \
             Enable feature in Cargo.toml: ghostfs = {{ features = [\"grpc-tls\"] }}"
        );
        // Drain events loop — nie streamuj bez TLS.
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        let mut rx   = streamer.subscribe();
        loop {
            tokio::select! {
                ev = rx.recv() => {
                    if let Ok(e) = ev { log::debug!("forensics (no-tls drain): seq={}", e.seq); }
                }
                _ = listener.accept() => {
                    log::warn!("gRPC forensics: rejected connection (TLS not available)");
                }
            }
        }
    }
}
