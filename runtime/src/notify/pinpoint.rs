//! Waking devices through AWS End User Messaging Push, the service that was Amazon Pinpoint.
//!
//! # The credential is not here
//!
//! The Firebase key lives on the push application's FCM channel, inside AWS. This image names
//! the application and signs each request with the instance's own role, fetched from the
//! metadata service when it is needed: there is no secret in the image to read, and none in a
//! bundle published from it.
//!
//! # The message carries nothing
//!
//! Every request built here is **data-only**. There is no `notification` object, no title and no
//! body, and that absence is the security property the whole feature rests on: the payload
//! crosses the parent instance, AWS and then Google, so anything put in it is disclosed to all
//! three. What travels is an opaque category and an optional tenant-local reference — labels the
//! guest chose, meaningful only to an app that can already reach the enclave.
//!
//! It is also the correct shape mechanically. A `notification` block is rendered by the OS
//! without the app running, so a wake that carried one would show text *and* fail to wake
//! anything.
//!
//! # It goes as `RawContent`, and only that
//!
//! Pinpoint's structured GCM fields wrap what they carry: `Data` reaches the phone as one string
//! under `pinpoint.jsonBody`, which an app reading `data.category` never finds — the wake is
//! accepted, reported delivered, and dropped on the device. `RawContent` is handed to FCM as
//! written, so what arrives is exactly the FCM v1 message this module builds, with the token
//! Pinpoint fills in from the address.
//!
//! # Errors are classified by what the service said
//!
//! Pinpoint answers 200 for a send it accepted and reports each address on its own, so a token
//! that is gone arrives as a 200 whose result says so, not as an HTTP error. Never matched on a
//! `Debug` string.

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{ensure, Result};
use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_credential_types::Credentials;

use super::transport::PushTransport;

/// The name requests are signed for. The host is `pinpoint.<region>.amazonaws.com`; this is
/// what IAM and SigV4 call the service.
const SERVICE: &str = "mobiletargeting";
/// A wake that arrives tomorrow is noise, not a notification. FCM's own default is four weeks.
const TTL_SECS: u64 = 3600;
/// How long one exchange may take, end to end, a credential fetch included.
///
/// Deliberately here rather than inside a transport: the forwarder sends to a tenant's devices
/// one after another, so an endpoint that accepts a connection and then says nothing would stop
/// *every* tenant's wakes for ever. Shorter than the forwarder's flush deadline, so a shutdown
/// can still finish inside its own bound.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);
/// A credential this close to expiring is fetched again rather than used: a signature made with
/// it could arrive after it lapsed.
const CREDENTIAL_MARGIN: Duration = Duration::from_secs(300);

/// How to reach the push application.
pub struct NotifyConfig {
    /// The push application, which holds the FCM channel and its credential.
    pub app_id: String,
    /// Where the application lives, and the region requests are signed for.
    pub region: String,
    /// For tests and the emulator's stub. A downgrade path: pointed at a plain `http://` stub it
    /// hands wake signals to whatever is listening. Only a `testing` build can set it.
    pub endpoint: Option<String>,
    /// What signs: the instance's role in an enclave, never a key in the image.
    pub credentials: SharedCredentialsProvider,
}

impl std::fmt::Debug for NotifyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyConfig")
            .field("app_id", &self.app_id)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// The instance's role, from the metadata service and from nowhere else.
///
/// Not the default chain: that tries the environment first, and an emulator's environment holds
/// its object store's keys. In an enclave the metadata service is reached through the address
/// `AWS_EC2_METADATA_SERVICE_ENDPOINT` names, which gvproxy maps for the runtime alone.
pub fn instance_role() -> SharedCredentialsProvider {
    SharedCredentialsProvider::new(
        aws_config::imds::credentials::ImdsCredentialsProvider::builder().build(),
    )
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

/// The FCM v1 message a wake is, without the token Pinpoint fills in from the address.
///
/// Public so a test can assert on exactly what would go on the wire, which is the only part of
/// this module worth pinning byte for byte.
pub fn wake_message(category: &str, reference: Option<&str>, now_ms: u64) -> serde_json::Value {
    let mut data = serde_json::Map::new();
    // A schema version the app can switch on. Free now, impossible to add later without a
    // release that understands both.
    data.insert("v".into(), "1".into());
    data.insert("category".into(), category.into());
    if let Some(reference) = reference {
        data.insert("ref".into(), reference.into());
    }

    serde_json::json!({
        // Data-only. See the module docs: there is no `notification` key here, and adding one
        // would disclose its contents to the parent instance, AWS and Google.
        "data": data,
        // High priority so a data-only message is delivered in Doze. Android meters this, so a
        // chatty guest is throttled by the platform rather than by us.
        "android": { "priority": "high", "ttl": format!("{TTL_SECS}s") },
        // The only combination APNs accepts for a silent wake: a background push type with
        // content-available, at priority 5. Priority 10 with a background type is rejected.
        "apns": {
            "headers": {
                "apns-push-type": "background",
                "apns-priority": "5",
                "apns-expiration": (now_ms / 1000 + TTL_SECS).to_string(),
            },
            "payload": { "aps": { "content-available": 1 } },
        },
    })
}

/// The `SendMessages` body for one wake to one device: the message as `RawContent`, and nothing
/// beside it — see the module docs.
pub fn wake_request(
    token: &str,
    category: &str,
    reference: Option<&str>,
    now_ms: u64,
) -> serde_json::Value {
    let raw = serde_json::json!({
        "fcmV1Message": { "message": wake_message(category, reference, now_ms) }
    });
    serde_json::json!({
        "Addresses": { token: { "ChannelType": "GCM" } },
        "MessageConfiguration": { "GCMMessage": { "RawContent": raw.to_string() } },
    })
}

/// What an error response says, for a status that is not 200.
fn classify_status(response: &http::Response<Vec<u8>>) -> SendError {
    let status = response.status().as_u16();
    let kind = response
        .headers()
        .get("x-amzn-errortype")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let detail = format!(
        "{status} {kind}: {}",
        String::from_utf8_lossy(response.body())
    );
    match status {
        // A request that will never be accepted, an application that does not exist, or a role
        // that is not allowed to send: none of these heal by waiting.
        400 | 404 | 413 => SendError::Refused(detail),
        403 if kind.starts_with("AccessDenied") => SendError::Refused(detail),
        // Any other 403 is a signature the service would not take — a credential that expired
        // in flight, a clock out of step — and heals with fresh credentials.
        _ => SendError::Transient(detail),
    }
}

/// What the service said about the one address a wake was sent to.
fn classify_send(response: &http::Response<Vec<u8>>, token: &str) -> Result<(), SendError> {
    if response.status().as_u16() != 200 {
        return Err(classify_status(response));
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(response.body()).unwrap_or(serde_json::Value::Null);
    let result = &parsed["Result"][token];
    let status = result["DeliveryStatus"].as_str().unwrap_or_default();
    let code = result["StatusCode"].as_u64().unwrap_or_default();
    let message = result["StatusMessage"].as_str().unwrap_or_default();
    let detail = format!("{status} {code}: {message}");
    match status {
        "SUCCESSFUL" => Ok(()),
        // Pruning is not undone: a wallet that thinks its token enrolled never offers it again
        // until FCM rotates it. So only the answers that unmistakably mean "gone" prune.
        "PERMANENT_FAILURE"
            if matches!(code, 404 | 410)
                || message.contains("UNREGISTERED")
                || message.contains("NotRegistered") =>
        {
            Err(SendError::DeadToken(detail))
        }
        "PERMANENT_FAILURE" | "OPT_OUT" | "DUPLICATE" => Err(SendError::Refused(detail)),
        // Temporary, throttled, unknown, or no word about this address at all.
        _ => Err(SendError::Transient(detail)),
    }
}

/// The push half of notify: signs requests and sends wake signals.
///
/// Owned by the single forwarder task, so the credential cache is a plain field behind
/// `&mut self` — there is no refresh race to design against.
pub struct PinpointClient {
    config: NotifyConfig,
    transport: Arc<dyn PushTransport>,
    cached: Option<Credentials>,
}

impl std::fmt::Debug for PinpointClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinpointClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl PinpointClient {
    pub fn new(config: NotifyConfig, transport: Arc<dyn PushTransport>) -> Self {
        PinpointClient {
            config,
            transport,
            cached: None,
        }
    }

    fn endpoint(&self) -> String {
        match &self.config.endpoint {
            Some(endpoint) => endpoint.clone(),
            None => format!("https://pinpoint.{}.amazonaws.com", self.config.region),
        }
    }

    /// The credentials to sign with, fetched again shortly before they expire.
    async fn credentials(&mut self, now_ms: u64) -> std::result::Result<Credentials, SendError> {
        let now = UNIX_EPOCH + Duration::from_millis(now_ms);
        if let Some(cached) = &self.cached {
            if cached
                .expiry()
                .is_none_or(|expiry| expiry > now + CREDENTIAL_MARGIN)
            {
                return Ok(cached.clone());
            }
        }
        let fetched = tokio::time::timeout(
            EXCHANGE_TIMEOUT,
            self.config.credentials.provide_credentials(),
        )
        .await
        .map_err(|_| {
            SendError::Transient(format!(
                "no credentials from the instance role within {EXCHANGE_TIMEOUT:?}"
            ))
        })?
        .map_err(|e| SendError::Transient(format!("fetching credentials: {e}")))?;
        self.cached = Some(fetched.clone());
        Ok(fetched)
    }

    /// Sign `body` for `method` `uri` and send it, never waiting on it for ever.
    ///
    /// Signed at `now_ms`, the trusted clock's time, not the host's: the parent sets the host
    /// clock, and a signature dated by it is one the parent can make expire.
    async fn signed(
        &mut self,
        method: http::Method,
        uri: &str,
        body: Vec<u8>,
        now_ms: u64,
    ) -> std::result::Result<http::Response<Vec<u8>>, SendError> {
        let credentials = self.credentials(now_ms).await?;
        let mut request = http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(body)
            .map_err(|e| SendError::Refused(format!("building the request: {e}")))?;
        sign(&mut request, credentials, &self.config.region, now_ms)?;

        let response =
            match tokio::time::timeout(EXCHANGE_TIMEOUT, self.transport.send(request)).await {
                Ok(Ok(response)) => response,
                Ok(Err(e)) => return Err(SendError::Transient(format!("reaching {uri}: {e}"))),
                Err(_) => {
                    return Err(SendError::Transient(format!(
                        "{uri} did not answer within {EXCHANGE_TIMEOUT:?}"
                    )))
                }
            };
        // A refused signature heals with credentials fetched again, whatever else it means.
        if response.status().as_u16() == 403 {
            self.cached = None;
        }
        Ok(response)
    }

    /// Prove the application can deliver, without waking anybody.
    ///
    /// Reading the FCM channel needs a signature the service accepts, and its answer says
    /// whether a send could ever work: a channel that is off, has no Firebase credential, or
    /// would use the legacy server key Google has turned off is a deployment mistake, and
    /// finding it at boot beats finding it the first time somebody needed a wake.
    pub async fn probe(&mut self, now_ms: u64) -> std::result::Result<(), SendError> {
        let uri = format!(
            "{}/v1/apps/{}/channels/gcm",
            self.endpoint(),
            self.config.app_id
        );
        let response = self
            .signed(http::Method::GET, &uri, Vec::new(), now_ms)
            .await?;
        if response.status().as_u16() != 200 {
            return Err(classify_status(&response));
        }
        let channel: serde_json::Value =
            serde_json::from_slice(response.body()).unwrap_or(serde_json::Value::Null);
        let ready = channel["Enabled"] == true
            && channel["HasFcmServiceCredentials"] == true
            && channel["DefaultAuthenticationMethod"] == "TOKEN";
        if ready {
            Ok(())
        } else {
            Err(SendError::Refused(format!(
                "the push application's FCM channel must be enabled, hold a Firebase service \
                 account, and authenticate with TOKEN: Enabled={} HasFcmServiceCredentials={} \
                 DefaultAuthenticationMethod={}",
                channel["Enabled"],
                channel["HasFcmServiceCredentials"],
                channel["DefaultAuthenticationMethod"]
            )))
        }
    }

    /// Send one wake signal to one device.
    pub async fn wake(
        &mut self,
        token: &str,
        category: &str,
        reference: Option<&str>,
        now_ms: u64,
    ) -> std::result::Result<(), SendError> {
        let body = serde_json::to_vec(&wake_request(token, category, reference, now_ms))
            .map_err(|e| SendError::Refused(format!("encoding the message: {e}")))?;
        let uri = format!(
            "{}/v1/apps/{}/messages",
            self.endpoint(),
            self.config.app_id
        );
        let response = self.signed(http::Method::POST, &uri, body, now_ms).await?;
        classify_send(&response, token)
    }
}

/// SigV4 for the push service, at `now_ms`.
fn sign(
    request: &mut http::Request<Vec<u8>>,
    credentials: Credentials,
    region: &str,
    now_ms: u64,
) -> std::result::Result<(), SendError> {
    use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings};
    use aws_sigv4::sign::v4;

    let failed = |e: &dyn std::fmt::Display| SendError::Transient(format!("signing: {e}"));
    let identity = credentials.into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(SERVICE)
        .time(UNIX_EPOCH + Duration::from_millis(now_ms))
        .settings(SigningSettings::default())
        .build()
        .map_err(|e| failed(&e))?
        .into();
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_string())))
        .collect();
    let uri = request.uri().to_string();
    let instructions = {
        let signable = SignableRequest::new(
            request.method().as_str(),
            uri.as_str(),
            headers.iter().map(|(n, v)| (n.as_str(), v.as_str())),
            SignableBody::Bytes(request.body()),
        )
        .map_err(|e| failed(&e))?;
        aws_sigv4::http_request::sign(signable, &params)
            .map_err(|e| failed(&e))?
            .into_parts()
            .0
    };
    instructions.apply_to_request_http1x(request);
    Ok(())
}

/// Labels are identifiers, not prose. The charset is what keeps them out of trouble in JSON, in
/// logs, and in whatever the app switches on.
pub const MAX_LABEL: usize = 64;

pub fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
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

/// Whether `app_id` can be a push application's id: it goes into a URL path, so nothing but
/// letters and digits.
pub fn valid_app_id(app_id: &str) -> bool {
    !app_id.is_empty() && app_id.len() <= 64 && app_id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Build the client the runtime actually uses.
pub fn client(config: NotifyConfig, transport: Arc<dyn PushTransport>) -> Result<PinpointClient> {
    ensure!(
        valid_app_id(&config.app_id),
        "a push application id is 1-64 letters and digits"
    );
    Ok(PinpointClient::new(config, transport))
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::Mutex;

    /// Records what was sent and answers from a script.
    #[derive(Debug, Default)]
    pub struct Recorder {
        pub sent: Mutex<Vec<http::Request<Vec<u8>>>>,
        /// Answers, consumed in order. The last one repeats once exhausted. A body of `SENT`
        /// is replaced by a successful result for whichever address the request named.
        pub replies: Mutex<Vec<(u16, String)>>,
        /// When set, every send hangs — standing in for a push service that has stopped
        /// answering.
        pub stall: std::sync::atomic::AtomicBool,
    }

    /// A reply meaning "delivered", for whatever address was asked about.
    pub const SENT: &str = "SENT";

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

        /// Every `SendMessages` body that was sent.
        pub fn messages(&self) -> Vec<serde_json::Value> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.uri().path().ends_with("/messages"))
                .map(|r| serde_json::from_slice(r.body()).expect("a JSON body"))
                .collect()
        }

        /// The FCM v1 messages inside them.
        pub fn fcm_messages(&self) -> Vec<serde_json::Value> {
            self.messages()
                .iter()
                .map(|m| {
                    let raw = m["MessageConfiguration"]["GCMMessage"]["RawContent"]
                        .as_str()
                        .expect("RawContent");
                    let raw: serde_json::Value = serde_json::from_str(raw).expect("JSON");
                    raw["fcmV1Message"]["message"].clone()
                })
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
    impl PushTransport for Recorder {
        async fn send(
            &self,
            request: http::Request<Vec<u8>>,
        ) -> std::result::Result<http::Response<Vec<u8>>, String> {
            if self.stall.load(std::sync::atomic::Ordering::Relaxed) {
                std::future::pending::<()>().await;
            }
            let address = serde_json::from_slice::<serde_json::Value>(request.body())
                .ok()
                .and_then(|b| b["Addresses"].as_object()?.keys().next().cloned())
                .unwrap_or_default();
            self.sent.lock().unwrap().push(request);
            let mut replies = self.replies.lock().unwrap();
            let (status, body) = if replies.len() > 1 {
                replies.remove(0)
            } else {
                replies.first().cloned().unwrap_or((200, SENT.to_string()))
            };
            let body = if body == SENT {
                serde_json::json!({"ApplicationId": "app", "Result": {
                    address: {"DeliveryStatus": "SUCCESSFUL", "StatusCode": 200}}})
                .to_string()
            } else {
                body
            };
            Ok(http::Response::builder()
                .status(status)
                .body(body.into_bytes())
                .unwrap())
        }
    }

    /// A credential that counts how often it is asked for.
    #[derive(Debug, Default)]
    pub struct Counted {
        pub asked: std::sync::atomic::AtomicUsize,
        /// Seconds after the epoch each credential handed out expires, or none.
        pub expires_secs: Option<u64>,
    }

    impl ProvideCredentials for Counted {
        fn provide_credentials<'a>(
            &'a self,
        ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            self.asked
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            aws_credential_types::provider::future::ProvideCredentials::ready(Ok(Credentials::new(
                "AKIDEXAMPLE",
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                Some("session-token".into()),
                self.expires_secs
                    .map(|s| UNIX_EPOCH + Duration::from_secs(s)),
                "test",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{Counted, Recorder, SENT};
    use super::*;

    const TOKEN: &str = "cWWpFzVAQ0y7Zb3hJ8kLmN:APA91bHqRsTuVwXyZ0123456789abcdef";
    /// 2026-01-04T12:00:00Z.
    const NOW_MS: u64 = 1_767_528_000_000;

    fn client_with(recorder: Arc<Recorder>) -> PinpointClient {
        client_counting(recorder, Arc::new(Counted::default()))
    }

    fn client_counting(recorder: Arc<Recorder>, credentials: Arc<Counted>) -> PinpointClient {
        PinpointClient::new(
            NotifyConfig {
                app_id: "0123456789abcdef0123456789abcdef".into(),
                region: "eu-west-2".into(),
                endpoint: None,
                credentials: SharedCredentialsProvider::new(CountedRef(credentials)),
            },
            recorder,
        )
    }

    /// `Arc<Counted>` as a provider, so a test can keep counting after handing it over.
    #[derive(Debug)]
    struct CountedRef(Arc<Counted>);
    impl ProvideCredentials for CountedRef {
        fn provide_credentials<'a>(
            &'a self,
        ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            self.0.provide_credentials()
        }
    }

    fn result(status: &str, code: u16, message: &str) -> String {
        serde_json::json!({"ApplicationId": "app", "Result": {
            TOKEN: {"DeliveryStatus": status, "StatusCode": code, "StatusMessage": message}}})
        .to_string()
    }

    /// The claim the whole feature rests on, and the shape that keeps it reaching the app.
    #[tokio::test]
    async fn a_wake_is_raw_content_carrying_a_data_only_message() {
        let recorder = Recorder::with(vec![(200, SENT)]);
        let mut client = client_with(recorder.clone());
        client
            .wake(TOKEN, "approval-needed", Some("txn-9f2"), NOW_MS)
            .await
            .unwrap();

        let request = &recorder.messages()[0];
        let mut keys: Vec<_> = request.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["Addresses", "MessageConfiguration"], "{request}");
        assert_eq!(request["Addresses"][TOKEN]["ChannelType"], "GCM");
        let gcm = request["MessageConfiguration"]["GCMMessage"]
            .as_object()
            .unwrap();
        assert_eq!(
            gcm.keys().collect::<Vec<_>>(),
            ["RawContent"],
            "a structured field would wrap the data where the app never looks: {gcm:?}"
        );
        assert_eq!(
            request["MessageConfiguration"]
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            ["GCMMessage"]
        );

        let message = &recorder.fcm_messages()[0];
        assert!(
            message["notification"].is_null(),
            "a wake signal carried a notification block: {message}"
        );
        assert!(message["token"].is_null(), "the address carries the token");
        assert_eq!(message["data"]["category"], "approval-needed");
        assert_eq!(message["data"]["ref"], "txn-9f2");
        assert_eq!(message["data"]["v"], "1");
        let data = message["data"].as_object().unwrap();
        let mut keys: Vec<_> = data.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["category", "ref", "v"]);
    }

    /// Signed for the push service, in the application's region, at the trusted clock's time —
    /// never the host's.
    #[tokio::test]
    async fn the_send_is_signed_for_the_push_service_at_the_trusted_time() {
        let recorder = Recorder::with(vec![(200, SENT)]);
        let mut client = client_with(recorder.clone());
        client.wake(TOKEN, "ping", None, NOW_MS).await.unwrap();

        let sent = recorder.requests();
        let request = &sent[0];
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(
            request.uri().to_string(),
            "https://pinpoint.eu-west-2.amazonaws.com/v1/apps/0123456789abcdef0123456789abcdef/messages"
        );
        let authorization = request.headers()["authorization"].to_str().unwrap();
        assert!(
            authorization.starts_with(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260104/eu-west-2/mobiletargeting/aws4_request,"
            ),
            "{authorization}"
        );
        assert_eq!(request.headers()["x-amz-date"], "20260104T120000Z");
        assert_eq!(request.headers()["x-amz-security-token"], "session-token");
    }

    #[tokio::test]
    async fn an_ios_wake_is_a_background_push_and_an_android_wake_is_high_priority() {
        let message = wake_message("ping", None, 1_000_000);
        assert_eq!(message["android"]["priority"], "high");
        assert_eq!(message["apns"]["headers"]["apns-push-type"], "background");
        assert_eq!(message["apns"]["headers"]["apns-priority"], "5");
        assert_eq!(message["apns"]["payload"]["aps"]["content-available"], 1);
    }

    #[test]
    fn a_wake_expires_rather_than_arriving_a_day_late() {
        let message = wake_message("ping", None, 1_000_000);
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
    async fn each_answer_about_an_address_is_classified_by_what_it_says() {
        for (reply, expect) in [
            (result("SUCCESSFUL", 200, ""), "ok"),
            (result("PERMANENT_FAILURE", 404, "Not found"), "dead"),
            (result("PERMANENT_FAILURE", 410, ""), "dead"),
            (result("PERMANENT_FAILURE", 400, "UNREGISTERED"), "dead"),
            (
                result("PERMANENT_FAILURE", 400, "InvalidRegistration"),
                "refused",
            ),
            (result("OPT_OUT", 400, ""), "refused"),
            (result("DUPLICATE", 400, ""), "refused"),
            (result("TEMPORARY_FAILURE", 503, ""), "transient"),
            (result("THROTTLED", 429, ""), "transient"),
            (result("UNKNOWN_FAILURE", 500, ""), "transient"),
            ("{\"Result\":{}}".to_string(), "transient"),
        ] {
            let recorder = Recorder::with(vec![(200, &reply)]);
            let mut client = client_with(recorder);
            let got = match client.wake(TOKEN, "ping", None, NOW_MS).await {
                Ok(()) => "ok",
                Err(SendError::DeadToken(_)) => "dead",
                Err(SendError::Refused(_)) => "refused",
                Err(SendError::Transient(_)) => "transient",
            };
            assert_eq!(got, expect, "{reply}");
        }
    }

    #[test]
    fn an_error_status_is_refused_only_when_it_cannot_heal() {
        for (status, kind, expect) in [
            (400, "BadRequestException", "refused"),
            (404, "NotFoundException", "refused"),
            (403, "AccessDeniedException", "refused"),
            (403, "InvalidSignatureException", "transient"),
            (429, "TooManyRequestsException", "transient"),
            (500, "InternalServerErrorException", "transient"),
        ] {
            // The kind travels in a header, so this classifies a response directly.
            let response = http::Response::builder()
                .status(status)
                .header("x-amzn-errortype", kind)
                .body(b"{}".to_vec())
                .unwrap();
            let got = match classify_send(&response, TOKEN) {
                Ok(()) => "ok",
                Err(SendError::Refused(_)) => "refused",
                Err(SendError::Transient(_)) => "transient",
                Err(SendError::DeadToken(_)) => "dead",
            };
            assert_eq!(got, expect, "{status} {kind}");
        }
    }

    /// The forwarder sends to a tenant's devices one after another, so an endpoint that accepts
    /// a connection and then says nothing would stop every tenant's wakes for ever. It has to
    /// come back as an ordinary transient failure instead.
    #[tokio::test(start_paused = true)]
    async fn an_endpoint_that_never_answers_is_transient_rather_than_a_hang() {
        let recorder = Recorder::with(vec![(200, SENT)]);
        recorder
            .stall
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut client = client_with(recorder);

        let err = client.wake(TOKEN, "ping", None, NOW_MS).await.unwrap_err();
        match err {
            SendError::Transient(detail) => {
                assert!(detail.contains("did not answer"), "unhelpful: {detail}")
            }
            other => panic!("a stalled endpoint was classified {other:?}"),
        }
    }

    #[tokio::test]
    async fn credentials_are_fetched_once_and_again_before_they_expire() {
        let counted = Arc::new(Counted {
            // An hour after NOW_MS.
            expires_secs: Some(NOW_MS / 1000 + 3600),
            ..Default::default()
        });
        let recorder = Recorder::with(vec![(200, SENT)]);
        let mut client = client_counting(recorder, counted.clone());
        for _ in 0..3 {
            client.wake(TOKEN, "ping", None, NOW_MS).await.unwrap();
        }
        let asked = || counted.asked.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(asked(), 1, "credentials were fetched per send");

        // Inside the margin before expiry: fetched again.
        let later = NOW_MS + 3_600_000 - CREDENTIAL_MARGIN.as_millis() as u64 + 1;
        client.wake(TOKEN, "ping", None, later).await.unwrap();
        assert_eq!(asked(), 2, "a credential about to expire was used");
    }

    #[tokio::test]
    async fn a_refused_signature_fetches_credentials_again() {
        let counted = Arc::new(Counted::default());
        let recorder = Recorder::with(vec![(403, "{}"), (200, SENT)]);
        let mut client = client_counting(recorder, counted.clone());
        assert!(matches!(
            client.wake(TOKEN, "ping", None, NOW_MS).await.unwrap_err(),
            SendError::Transient(_)
        ));
        client.wake(TOKEN, "ping", None, NOW_MS).await.unwrap();
        assert_eq!(counted.asked.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn the_probe_reads_the_channel_and_wakes_nobody() {
        let ready = serde_json::json!({"Enabled": true, "HasFcmServiceCredentials": true,
                                      "DefaultAuthenticationMethod": "TOKEN"})
        .to_string();
        let recorder = Recorder::with(vec![(200, &ready)]);
        let mut client = client_with(recorder.clone());
        client.probe(NOW_MS).await.unwrap();
        assert!(
            recorder.messages().is_empty(),
            "the startup probe sent a message to a real device"
        );
        let sent = recorder.requests();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].method(), http::Method::GET);
        assert!(sent[0].uri().path().ends_with("/channels/gcm"));
    }

    /// A channel that could never deliver stops the boot: the legacy server key is gone at
    /// Google, and `KEY` is the channel's default.
    #[tokio::test]
    async fn a_channel_that_cannot_deliver_is_refused() {
        for channel in [
            serde_json::json!({"Enabled": true, "HasFcmServiceCredentials": true,
                               "DefaultAuthenticationMethod": "KEY"}),
            serde_json::json!({"Enabled": false, "HasFcmServiceCredentials": true,
                               "DefaultAuthenticationMethod": "TOKEN"}),
            serde_json::json!({"Enabled": true, "HasFcmServiceCredentials": false,
                               "DefaultAuthenticationMethod": "TOKEN"}),
        ] {
            let recorder = Recorder::with(vec![(200, &channel.to_string())]);
            let mut client = client_with(recorder);
            assert!(
                matches!(client.probe(NOW_MS).await, Err(SendError::Refused(_))),
                "{channel}"
            );
        }
    }

    #[test]
    fn a_debug_line_shows_no_secret() {
        let client = client_with(Recorder::with(vec![]));
        let shown = format!("{client:?}");
        assert!(!shown.contains("wJalrXUtnFEMI"), "{shown}");
        assert!(shown.contains("eu-west-2"), "{shown}");
    }

    #[test]
    fn an_app_id_is_letters_and_digits() {
        assert!(valid_app_id("0123456789abcdef0123456789abcdef"));
        assert!(valid_app_id("e2e"));
        assert!(!valid_app_id(""));
        assert!(!valid_app_id("../channels"));
        assert!(!valid_app_id(&"a".repeat(65)));
    }
}
