//! Talking to Firebase Cloud Messaging.
//!
//! # The message carries nothing
//!
//! Every request built here is **data-only**. There is no `notification`
//! object, no title and no body, and that absence is the security property the
//! whole feature rests on: the payload crosses the parent instance and then
//! Google, so anything put in it is disclosed to both. What travels is an
//! opaque category and an optional tenant-local reference — labels the guest
//! chose, meaningful only to an app that can already reach the enclave.
//!
//! It is also the correct shape mechanically. A `notification` block is
//! rendered by the OS without the app running, so a wake that carried one would
//! show text *and* fail to wake anything.
//!
//! # Errors are classified by what the service said
//!
//! Never by matching on a `Debug` string. FCM names its own failures, and the
//! three that matter are told apart by name: a token that is gone, a message
//! that will never be accepted, and everything else — which is worth retrying,
//! credential failures included, because those heal on the next refresh.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Result};

use super::oauth::{AccessToken, ServiceAccount, TokenResponse};

/// Where FCM lives, unless a deployment points somewhere else.
const DEFAULT_ENDPOINT: &str = "https://fcm.googleapis.com";
/// A wake that arrives tomorrow is noise, not a notification. FCM's own default
/// is four weeks.
const TTL_SECS: u64 = 3600;
/// How long one exchange with FCM may take, end to end.
///
/// Deliberately here rather than inside a transport: the forwarder sends to a
/// tenant's devices one after another, so an endpoint that accepts a connection
/// and then says nothing would stop *every* tenant's wakes for ever. Shorter
/// than the forwarder's flush deadline, so a shutdown can still finish inside
/// its own bound.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);

/// Labels are identifiers, not prose. The charset is what keeps them out of
/// trouble in JSON, in logs, and in whatever the app switches on.
const MAX_LABEL: usize = 64;

/// How to reach FCM.
pub struct NotifyConfig {
    pub project_id: String,
    pub service_account: ServiceAccount,
    /// For tests and local endpoints. A downgrade path: pointed at a plain
    /// `http://` stub it hands wake signals to whatever is listening. PCR0
    /// records which was built, which is the only reason this is acceptable.
    pub endpoint: Option<String>,
}

impl std::fmt::Debug for NotifyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyConfig")
            .field("project_id", &self.project_id)
            .field("service_account", &self.service_account)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// One HTTP exchange. The seam that keeps the network out of the tests.
#[async_trait::async_trait]
pub trait FcmTransport: Send + Sync + std::fmt::Debug {
    async fn send(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> std::result::Result<http::Response<Vec<u8>>, String>;
}

/// What went wrong, in the only three shapes the caller acts on differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// This registration token is gone. Prune it; never retry it.
    DeadToken(String),
    /// This message will never be accepted. Drop it and count it.
    Refused(String),
    /// Worth trying again, credential failures included.
    Transient(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::DeadToken(m) => write!(f, "registration token is gone: {m}"),
            SendError::Refused(m) => write!(f, "refused: {m}"),
            SendError::Transient(m) => write!(f, "transient: {m}"),
        }
    }
}

pub fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// The body of a wake signal.
///
/// Public so a test can assert on exactly what would go on the wire, which is
/// the only part of this module worth pinning byte for byte.
pub fn wake_message(
    token: &str,
    category: &str,
    reference: Option<&str>,
    now_ms: u64,
) -> serde_json::Value {
    let mut data = serde_json::Map::new();
    // A schema version the app can switch on. Free now, impossible to add
    // later without a release that understands both.
    data.insert("v".into(), "1".into());
    data.insert("category".into(), category.into());
    if let Some(reference) = reference {
        data.insert("ref".into(), reference.into());
    }

    serde_json::json!({
        "message": {
            "token": token,
            // Data-only. See the module docs: there is no `notification` key
            // here, and adding one would disclose its contents to the parent
            // instance and to Google.
            "data": data,
            // High priority so a data-only message is delivered in Doze.
            // Android meters this, so a chatty guest is throttled by the
            // platform rather than by us.
            "android": { "priority": "high", "ttl": format!("{TTL_SECS}s") },
            // The only combination APNs accepts for a silent wake: a
            // background push type with content-available, at priority 5.
            // Priority 10 with a background type is rejected outright.
            "apns": {
                "headers": {
                    "apns-push-type": "background",
                    "apns-priority": "5",
                    "apns-expiration": (now_ms / 1000 + TTL_SECS).to_string(),
                },
                "payload": { "aps": { "content-available": 1 } },
            },
        }
    })
}

/// Reads FCM's own error name out of a response.
fn classify(status: u16, body: &[u8]) -> SendError {
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let code = parsed["error"]["details"]
        .as_array()
        .and_then(|details| {
            details
                .iter()
                .find_map(|d| d["errorCode"].as_str().map(str::to_string))
        })
        .or_else(|| parsed["error"]["status"].as_str().map(str::to_string))
        .unwrap_or_default();
    let message = parsed["error"]["message"]
        .as_str()
        .unwrap_or("no message")
        .to_string();
    let detail = format!("{status} {code}: {message}");

    match code.as_str() {
        "UNREGISTERED" | "NOT_FOUND" => SendError::DeadToken(detail),
        "INVALID_ARGUMENT" | "SENDER_ID_MISMATCH" | "THIRD_PARTY_AUTH_ERROR" => {
            SendError::Refused(detail)
        }
        // Credentials stay transient on purpose: an expired token heals on the
        // next refresh, and treating it as fatal turns routine rotation into
        // an outage.
        _ => SendError::Transient(detail),
    }
}

/// The FCM half of notify: mints access tokens and sends wake signals.
///
/// Owned by the single forwarder task, so the token cache is a plain field
/// behind `&mut self` — there is no refresh race to design against.
#[derive(Debug)]
pub struct FcmClient {
    config: NotifyConfig,
    transport: Arc<dyn FcmTransport>,
    cached: Option<AccessToken>,
}

impl FcmClient {
    pub fn new(config: NotifyConfig, transport: Arc<dyn FcmTransport>) -> Self {
        FcmClient {
            config,
            transport,
            cached: None,
        }
    }

    /// Send one request, and never wait on it for ever.
    async fn exchange(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> std::result::Result<http::Response<Vec<u8>>, SendError> {
        let uri = request.uri().to_string();
        match tokio::time::timeout(EXCHANGE_TIMEOUT, self.transport.send(request)).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(SendError::Transient(format!("reaching {uri}: {e}"))),
            Err(_) => Err(SendError::Transient(format!(
                "{uri} did not answer within {EXCHANGE_TIMEOUT:?}"
            ))),
        }
    }

    fn endpoint(&self) -> &str {
        self.config.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT)
    }

    /// Mint an access token, or reuse the one we have.
    async fn access_token(&mut self, now_ms: u64) -> std::result::Result<String, SendError> {
        if let Some(token) = &self.cached {
            if token.is_fresh(now_ms) {
                return Ok(token.token.to_string());
            }
        }

        let assertion = self
            .config
            .service_account
            .assertion(now_ms)
            .map_err(|e| SendError::Transient(format!("signing the assertion: {e:#}")))?;
        let body = self.config.service_account.token_form(&assertion);
        let request = http::Request::builder()
            .method("POST")
            .uri(&self.config.service_account.token_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.into_bytes())
            .map_err(|e| SendError::Transient(format!("building the token request: {e}")))?;

        let response = self.exchange(request).await?;
        let status = response.status().as_u16();
        if status != 200 {
            let body = String::from_utf8_lossy(response.body()).to_string();
            let parsed: serde_json::Value =
                serde_json::from_slice(response.body()).unwrap_or(serde_json::Value::Null);
            let detail = format!("the token endpoint answered {status}: {body}");
            // `invalid_client` and `unauthorized_client` name a credential that
            // will never work, so the startup probe can refuse to boot on them.
            // `invalid_grant` deliberately is not in that set: it is as likely
            // to be a clock a minute out as a bad key, and an enclave that
            // refused to start over clock skew would be worse than one that
            // retries. See the note in `oauth`.
            return Err(match parsed["error"].as_str().unwrap_or_default() {
                "invalid_client" | "unauthorized_client" => SendError::Refused(detail),
                _ => SendError::Transient(detail),
            });
        }

        let parsed: TokenResponse = serde_json::from_slice(response.body())
            .map_err(|e| SendError::Transient(format!("decoding the token response: {e}")))?;
        let token = AccessToken::new(parsed, now_ms);
        let value = token.token.to_string();
        self.cached = Some(token);
        Ok(value)
    }

    /// Prove the credential works, without waking anybody.
    ///
    /// Minting a token needs exactly the permission sending needs, so this is a
    /// real check rather than a reachability ping — and it disturbs no device.
    pub async fn probe(&mut self, now_ms: u64) -> std::result::Result<(), SendError> {
        self.access_token(now_ms).await.map(|_| ())
    }

    /// Send one wake signal to one device.
    pub async fn wake(
        &mut self,
        token: &str,
        category: &str,
        reference: Option<&str>,
        now_ms: u64,
    ) -> std::result::Result<(), SendError> {
        let access = self.access_token(now_ms).await?;
        let body = serde_json::to_vec(&wake_message(token, category, reference, now_ms))
            .map_err(|e| SendError::Refused(format!("encoding the message: {e}")))?;
        let uri = format!(
            "{}/v1/projects/{}/messages:send",
            self.endpoint(),
            self.config.project_id
        );

        let send = |access: &str, body: &[u8]| {
            http::Request::builder()
                .method("POST")
                .uri(&uri)
                .header("authorization", format!("Bearer {access}"))
                .header("content-type", "application/json; charset=utf-8")
                .body(body.to_vec())
        };

        let request = send(&access, &body)
            .map_err(|e| SendError::Refused(format!("building the request: {e}")))?;
        let response = self.exchange(request).await?;

        let status = response.status().as_u16();
        if status == 200 {
            return Ok(());
        }
        // One retry on 401, and exactly one: the cached token may simply have
        // been revoked early. A second 401 is transient with backoff, never a
        // refresh loop.
        if status == 401 {
            self.cached = None;
            let access = self.access_token(now_ms).await?;
            let request = send(&access, &body)
                .map_err(|e| SendError::Refused(format!("building the request: {e}")))?;
            let response = self.exchange(request).await?;
            if response.status().as_u16() == 200 {
                return Ok(());
            }
            return Err(classify(response.status().as_u16(), response.body()));
        }
        Err(classify(status, response.body()))
    }
}

/// Validate what a guest supplied before any of it reaches a request.
pub fn check_labels(category: &str, reference: Option<&str>) -> Result<()> {
    ensure!(
        valid_label(category),
        "a category is 1-{MAX_LABEL} characters of letters, digits, '-' or '_'. \
         It is a label, not a message: a wake signal carries no text."
    );
    if let Some(reference) = reference {
        ensure!(
            valid_label(reference),
            "a reference is 1-{MAX_LABEL} characters of letters, digits, '-' or '_'"
        );
    }
    Ok(())
}

/// Build the client the runtime actually uses.
pub fn client(config: NotifyConfig, transport: Arc<dyn FcmTransport>) -> Result<FcmClient> {
    ensure!(
        !config.project_id.trim().is_empty(),
        "an FCM project id is required"
    );
    Ok(FcmClient::new(config, transport))
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::Mutex;

    /// Records what was sent and answers from a script.
    #[derive(Debug, Default)]
    pub struct Recorder {
        pub sent: Mutex<Vec<http::Request<Vec<u8>>>>,
        /// Answers, consumed in order. The last one repeats once exhausted.
        pub replies: Mutex<Vec<(u16, String)>>,
        /// When set, every send hangs — standing in for a push service that
        /// has stopped answering.
        pub stall: std::sync::atomic::AtomicBool,
    }

    impl Recorder {
        pub fn with(replies: Vec<(u16, &str)>) -> Arc<Self> {
            Arc::new(Recorder {
                sent: Mutex::new(Vec::new()),
                replies: Mutex::new(
                    replies
                        .into_iter()
                        .map(|(s, b)| (s, b.to_string()))
                        .collect(),
                ),
                stall: std::sync::atomic::AtomicBool::new(false),
            })
        }

        /// Every request that was not the token exchange.
        pub fn messages(&self) -> Vec<serde_json::Value> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.uri().path().ends_with("messages:send"))
                .map(|r| serde_json::from_slice(r.body()).expect("a JSON body"))
                .collect()
        }

        pub fn requests(&self) -> Vec<http::Request<Vec<u8>>> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .map(|r| {
                    let mut clone = http::Request::builder()
                        .method(r.method().clone())
                        .uri(r.uri().clone());
                    for (name, value) in r.headers() {
                        clone = clone.header(name, value);
                    }
                    clone.body(r.body().clone()).unwrap()
                })
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl FcmTransport for Recorder {
        async fn send(
            &self,
            request: http::Request<Vec<u8>>,
        ) -> std::result::Result<http::Response<Vec<u8>>, String> {
            if self.stall.load(std::sync::atomic::Ordering::Relaxed) {
                std::future::pending::<()>().await;
            }
            let token_request = request.uri().path().ends_with("/token");
            self.sent.lock().unwrap().push(request);
            if token_request {
                return Ok(http::Response::builder()
                    .status(200)
                    .body(
                        serde_json::json!({"access_token": "ya29.test", "expires_in": 3600})
                            .to_string()
                            .into_bytes(),
                    )
                    .unwrap());
            }
            let mut replies = self.replies.lock().unwrap();
            let (status, body) = if replies.len() > 1 {
                replies.remove(0)
            } else {
                replies.first().cloned().unwrap_or((200, "{}".to_string()))
            };
            Ok(http::Response::builder()
                .status(status)
                .body(body.into_bytes())
                .unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Recorder;
    use super::*;

    const TOKEN: &str = "cWWpFzVAQ0y7Zb3hJ8kLmN:APA91bHqRsTuVwXyZ0123456789abcdef";

    fn account() -> ServiceAccount {
        ServiceAccount::parse(
            &serde_json::json!({
                "type": "service_account",
                "project_id": "enclave-test",
                "private_key_id": "kid-1",
                "private_key": include_str!("testdata/service-account-key.pem"),
                "client_email": "wake@enclave-test.iam.gserviceaccount.com",
            })
            .to_string(),
        )
        .unwrap()
    }

    fn client_with(recorder: Arc<Recorder>) -> FcmClient {
        FcmClient::new(
            NotifyConfig {
                project_id: "enclave-test".into(),
                service_account: account(),
                endpoint: None,
            },
            recorder,
        )
    }

    /// The claim the whole feature rests on.
    #[tokio::test]
    async fn a_wake_signal_is_data_only_and_carries_no_notification_block() {
        let recorder = Recorder::with(vec![(200, "{}")]);
        let mut client = client_with(recorder.clone());
        client
            .wake(TOKEN, "approval-needed", Some("txn-9f2"), 1_000_000)
            .await
            .unwrap();

        let message = &recorder.messages()[0]["message"];
        assert!(
            message["notification"].is_null(),
            "a wake signal carried a notification block: {message}"
        );
        assert_eq!(message["data"]["category"], "approval-needed");
        assert_eq!(message["data"]["ref"], "txn-9f2");
        assert_eq!(message["data"]["v"], "1");

        // Nothing beyond the labels and the fixed keys reached the wire.
        let data = message["data"].as_object().unwrap();
        let mut keys: Vec<_> = data.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["category", "ref", "v"]);
    }

    #[tokio::test]
    async fn the_send_names_the_project_and_carries_a_bearer_token() {
        let recorder = Recorder::with(vec![(200, "{}")]);
        let mut client = client_with(recorder.clone());
        client.wake(TOKEN, "ping", None, 0).await.unwrap();

        let sent = recorder.requests();
        let message = sent
            .iter()
            .find(|r| r.uri().path().ends_with("messages:send"))
            .expect("a send");
        assert_eq!(
            message.uri().to_string(),
            "https://fcm.googleapis.com/v1/projects/enclave-test/messages:send"
        );
        assert_eq!(
            message.headers()["authorization"],
            "Bearer ya29.test",
            "the send did not carry the minted access token"
        );
        assert_eq!(message.method(), http::Method::POST);
    }

    #[tokio::test]
    async fn an_ios_wake_is_a_background_push_and_an_android_wake_is_high_priority() {
        let recorder = Recorder::with(vec![(200, "{}")]);
        let mut client = client_with(recorder.clone());
        client.wake(TOKEN, "ping", None, 1_000_000).await.unwrap();

        let message = &recorder.messages()[0]["message"];
        assert_eq!(message["android"]["priority"], "high");
        assert_eq!(message["apns"]["headers"]["apns-push-type"], "background");
        assert_eq!(message["apns"]["headers"]["apns-priority"], "5");
        assert_eq!(message["apns"]["payload"]["aps"]["content-available"], 1);
    }

    #[tokio::test]
    async fn a_wake_expires_rather_than_arriving_a_day_late() {
        let recorder = Recorder::with(vec![(200, "{}")]);
        let mut client = client_with(recorder.clone());
        client.wake(TOKEN, "ping", None, 1_000_000).await.unwrap();

        let message = &recorder.messages()[0]["message"];
        assert_eq!(message["android"]["ttl"], "3600s");
        assert_eq!(
            message["apns"]["headers"]["apns-expiration"],
            (1000 + TTL_SECS).to_string()
        );
    }

    #[test]
    fn a_category_that_is_not_a_plain_label_never_reaches_the_wire() {
        assert!(check_labels("approval-needed", Some("txn_1")).is_ok());
        assert!(check_labels("", None).is_err());
        assert!(check_labels(&"x".repeat(MAX_LABEL + 1), None).is_err());
        assert!(
            check_labels("Approve $4,000 to Acme", None).is_err(),
            "prose was accepted as a category"
        );
        assert!(check_labels("ok", Some("a b")).is_err());
    }

    #[tokio::test]
    async fn an_unregistered_token_is_pruned_rather_than_retried() {
        let body = serde_json::json!({"error": {
            "status": "NOT_FOUND", "message": "Requested entity was not found.",
            "details": [{"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                         "errorCode": "UNREGISTERED"}]}})
        .to_string();
        let recorder = Recorder::with(vec![(404, &body)]);
        let mut client = client_with(recorder);
        let err = client.wake(TOKEN, "ping", None, 0).await.unwrap_err();
        assert!(
            matches!(err, SendError::DeadToken(_)),
            "a gone token was classified {err:?}"
        );
    }

    /// The forwarder sends to a tenant's devices one after another, so an
    /// endpoint that accepts a connection and then says nothing would stop
    /// every tenant's wakes for ever. It has to come back as an ordinary
    /// transient failure instead.
    #[tokio::test(start_paused = true)]
    async fn an_endpoint_that_never_answers_is_transient_rather_than_a_hang() {
        let recorder = Recorder::with(vec![(200, "{}")]);
        recorder
            .stall
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut client = client_with(recorder);

        let err = client.wake(TOKEN, "ping", None, 0).await.unwrap_err();
        match err {
            SendError::Transient(detail) => {
                assert!(detail.contains("did not answer"), "unhelpful: {detail}")
            }
            other => panic!("a stalled endpoint was classified {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_malformed_message_is_dropped_rather_than_retried_for_ever() {
        let body = serde_json::json!({"error": {
            "status": "INVALID_ARGUMENT", "message": "Invalid value at 'message.token'",
            "details": [{"errorCode": "INVALID_ARGUMENT"}]}})
        .to_string();
        let recorder = Recorder::with(vec![(400, &body)]);
        let mut client = client_with(recorder);
        assert!(matches!(
            client.wake(TOKEN, "ping", None, 0).await.unwrap_err(),
            SendError::Refused(_)
        ));
    }

    #[tokio::test]
    async fn a_throttled_or_unavailable_send_is_transient() {
        for (status, code) in [
            (429, "QUOTA_EXCEEDED"),
            (503, "UNAVAILABLE"),
            (500, "INTERNAL"),
        ] {
            let body =
                serde_json::json!({"error": {"status": code, "message": "later", "details": [{"errorCode": code}]}})
                    .to_string();
            let recorder = Recorder::with(vec![(status, &body)]);
            let mut client = client_with(recorder);
            assert!(
                matches!(
                    client.wake(TOKEN, "ping", None, 0).await.unwrap_err(),
                    SendError::Transient(_)
                ),
                "{code} was not treated as worth retrying"
            );
        }
    }

    /// An expired access token heals on the next refresh, so it must not be
    /// fatal — but it must not loop either.
    #[tokio::test]
    async fn an_unauthorized_send_is_retried_once_with_a_fresh_token() {
        let recorder = Recorder::with(vec![(401, "{}"), (200, "{}")]);
        let mut client = client_with(recorder.clone());
        client.wake(TOKEN, "ping", None, 0).await.unwrap();
        assert_eq!(
            recorder.messages().len(),
            2,
            "the send was not retried after a 401"
        );

        // And a second 401 gives up rather than refreshing for ever.
        let recorder = Recorder::with(vec![(401, "{}")]);
        let mut client = client_with(recorder.clone());
        assert!(matches!(
            client.wake(TOKEN, "ping", None, 0).await.unwrap_err(),
            SendError::Transient(_)
        ));
        assert_eq!(recorder.messages().len(), 2, "a 401 loop");
    }

    #[tokio::test]
    async fn a_cached_access_token_is_minted_once_for_many_sends() {
        let recorder = Recorder::with(vec![(200, "{}")]);
        let mut client = client_with(recorder.clone());
        for _ in 0..3 {
            client.wake(TOKEN, "ping", None, 1_000).await.unwrap();
        }
        let tokens = recorder
            .requests()
            .iter()
            .filter(|r| r.uri().path().ends_with("/token"))
            .count();
        assert_eq!(tokens, 1, "the access token was minted per send");
    }

    #[tokio::test]
    async fn the_probe_mints_a_token_and_wakes_nobody() {
        let recorder = Recorder::with(vec![(200, "{}")]);
        let mut client = client_with(recorder.clone());
        client.probe(0).await.unwrap();
        assert!(
            recorder.messages().is_empty(),
            "the startup probe sent a message to a real device"
        );
        assert_eq!(recorder.requests().len(), 1);
    }
}
