//! Firebase, as far as the harness is concerned.
//!
//! The runtime builds its own FCM transport inside `serve_component`, so a
//! harness cannot hand it a recording double without putting a testing-only
//! field on `ServeConfig`. Standing up a real endpoint instead is both less
//! invasive and a better test: the transport, the signed OAuth assertion, the
//! bearer header and the error classification are all the production ones. Only
//! the far end is not Google.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::Wake;
use crate::notify::{NotifyConfig, ServiceAccount};

const KEY: &str = include_str!("fcm-key.pem");

pub(super) struct Fcm {
    addr: SocketAddr,
    wakes: Arc<Mutex<Vec<Wake>>>,
}

impl Fcm {
    pub(super) async fn start() -> Result<Arc<Self>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let wakes = Arc::new(Mutex::new(Vec::new()));

        let recorded = wakes.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let _ = serve_one(&mut socket, &recorded).await;
                });
            }
        });

        Ok(Arc::new(Fcm { addr, wakes }))
    }

    pub(super) fn config(&self) -> Result<NotifyConfig> {
        let account = serde_json::json!({
            "type": "service_account",
            "project_id": "harness",
            "private_key_id": "harness",
            "private_key": KEY,
            "client_email": "wake@harness.iam.gserviceaccount.com",
            // The assertion's `aud` is this same string, so it has to name
            // where the exchange actually happens.
            "token_uri": format!("http://{}/token", self.addr),
        })
        .to_string();
        Ok(NotifyConfig {
            project_id: "harness".into(),
            service_account: ServiceAccount::parse(&account)
                .context("the harness service account")?,
            // `http://` is what tells the runtime plaintext is acceptable here.
            endpoint: Some(format!("http://{}", self.addr)),
        })
    }

    pub(super) fn wakes(&self) -> Vec<Wake> {
        self.wakes.lock().unwrap().clone()
    }
}

async fn serve_one(socket: &mut tokio::net::TcpStream, wakes: &Mutex<Vec<Wake>>) -> Result<()> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    // Read until the headers are complete, then until content-length is met.
    let (head_end, length) = loop {
        let read = socket.read(&mut buf).await?;
        if read == 0 {
            anyhow::bail!("closed before a request arrived");
        }
        raw.extend_from_slice(&buf[..read]);
        if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (end + 4, length);
        }
    };
    while raw.len() < head_end + length {
        let read = socket.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..read]);
    }

    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let path = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("")
        .to_string();
    let body = &raw[head_end..];

    let reply = if path.ends_with("/token") {
        // The runtime signed a real RS256 assertion to get here. Verifying it
        // would mean reimplementing Google; that the signing is genuine is
        // covered by `notify::oauth`'s own tests.
        serde_json::json!({"access_token": "harness", "expires_in": 3600})
    } else if path.ends_with("messages:send") {
        let message: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
        let data = &message["message"]["data"];
        wakes.lock().unwrap().push(Wake {
            category: data["category"].as_str().unwrap_or_default().to_string(),
            reference: data["ref"].as_str().map(str::to_string),
            token: message["message"]["token"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        });
        serde_json::json!({"name": "projects/harness/messages/stub"})
    } else {
        serde_json::json!({"error": {"status": "NOT_FOUND"}})
    };

    let encoded = reply.to_string();
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{encoded}",
                encoded.len()
            )
            .as_bytes(),
        )
        .await?;
    Ok(())
}
