//! The push service, as far as the harness is concerned.
//!
//! The runtime builds its own push transport inside `serve_component`, so a
//! harness cannot hand it a recording double without putting a testing-only
//! field on `ServeConfig`. Standing up a real endpoint instead is both less
//! invasive and a better test: the transport, the SigV4 signature, the probe and
//! the result classification are all the production ones. Only the far end is
//! not AWS.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::Wake;
use crate::notify::NotifyConfig;

pub(super) struct Push {
    addr: SocketAddr,
    wakes: Arc<Mutex<Vec<Wake>>>,
}

impl Push {
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

        Ok(Arc::new(Push { addr, wakes }))
    }

    pub(super) fn config(&self) -> Result<NotifyConfig> {
        Ok(NotifyConfig {
            app_id: "harness".into(),
            region: "eu-west-2".into(),
            // `http://` is what tells the runtime plaintext is acceptable here.
            endpoint: Some(format!("http://{}", self.addr)),
            // Signed for real, by a credential nothing checks: verifying SigV4 would mean
            // reimplementing AWS, and `notify::pinpoint`'s own tests pin the signature.
            credentials: aws_credential_types::provider::SharedCredentialsProvider::new(
                aws_credential_types::Credentials::new("harness", "harness", None, None, "harness"),
            ),
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

    let reply = if path.ends_with("/channels/gcm") {
        serde_json::json!({"Platform": "GCM", "Enabled": true,
                           "HasFcmServiceCredentials": true,
                           "DefaultAuthenticationMethod": "TOKEN"})
    } else if path.ends_with("/messages") {
        let request: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
        let raw = request["MessageConfiguration"]["GCMMessage"]["RawContent"]
            .as_str()
            .unwrap_or_default();
        let raw: serde_json::Value = serde_json::from_str(raw).unwrap_or_default();
        let data = &raw["fcmV1Message"]["message"]["data"];
        let mut result = serde_json::Map::new();
        for token in request["Addresses"]
            .as_object()
            .into_iter()
            .flat_map(|a| a.keys())
        {
            wakes.lock().unwrap().push(Wake {
                category: data["category"].as_str().unwrap_or_default().to_string(),
                reference: data["ref"].as_str().map(str::to_string),
                token: token.clone(),
            });
            result.insert(
                token.clone(),
                serde_json::json!({"DeliveryStatus": "SUCCESSFUL", "StatusCode": 200}),
            );
        }
        serde_json::json!({"ApplicationId": "harness", "Result": result})
    } else {
        serde_json::json!({"Message": "not found"})
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
