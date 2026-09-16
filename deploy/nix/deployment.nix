# Which store this enclave image belongs to.
#
# These are baked into the image, so PCR0 covers them — and that is the point.
# A state-origin receipt proves an enclave of a known image created this
# filesystem, but only if the host cannot point that image at a *different*
# bucket: an empty one has no receipt, so it would take the genesis path and
# serve a fresh empty filesystem with every check passing.
#
# The consequence is real and worth knowing before you hit it: **changing any
# value here changes PCR0**. Two deployments are two images, a KMS key policy
# pinned to one will not release to the other, and clients pin different
# measurements. The enclave's identity includes what it operates on.
#
# `S3FS_ID` is not a secret. It is the HKDF salt, so two filesystems under one
# master secret stay independent, and it must be supplied rather than read from
# the store: the keys that verify a root record derive from it, so taking it
# from the store would mean trusting the store to say which key checks its own
# signature.
{
  dataBucket = "CHANGE-ME-data";
  rootsBucket = "CHANGE-ME-roots";
  bucketPrefix = "";

  # 32 hex characters.
  fsId = "00000000000000000000000000000000";

  region = "eu-west-2";

  # Domains for the serving certificate. Required, and not only for browsers:
  # the runtime obtains its certificate over ACME and nothing else, so an empty
  # list means no certificate and no HTTPS at all. A platform authenticator
  # also refuses to attest against a certificate a browser does not trust, so a
  # deployment that authenticates needs a real domain here.
  tlsDomains = [ ];

  # The domain passkeys are scoped to, and the origin assertions must claim.
  #
  # Must be one of `tlsDomains`: a passkey is bound to a domain, and an
  # assertion carries the origin the page was served from, compared exactly.
  # Baked into the image, so PCR0 records which relying party an enclave will
  # accept assertions for — a client can verify that before trusting it with a
  # key.
  rpId = "CHANGE-ME.example.com";

  # Origins other than `https://${rpId}` that assertions may claim — native
  # apps, which never claim the web origin. An Android app claims
  # "android:apk-key-hash:<hash>", the unpadded base64url SHA-256 of the
  # certificate it is signed with; for a Play release that is the app signing
  # key, not the upload key. `keytool` prints the colon-separated hex form of
  # the same digest, which must be converted — the runtime refuses it at boot.
  #
  # Android lets an app claim this only if
  # `https://${rpId}/.well-known/assetlinks.json` lists it, so that file must
  # be served too. Measured by PCR0 like `rpId`: adding an app is a new image.
  webauthnAllowedOrigins = [ ];

  # Where guest stdout and stderr go, on top of the enclave console.
  #
  # Both must already exist — `deploy/tofu` creates them, and the enclave holds
  # `logs:PutLogEvents` and nothing more, so it cannot create them itself. They
  # are baked into the image and therefore measured by PCR0, which is why a
  # client can tell from an attestation where an enclave ships guest output.
  #
  # The group must match `aws_cloudwatch_log_group.guest` in `deploy/tofu`,
  # which names it "/${name_prefix}-${environment}/guest".
  guestLogGroup = "/CHANGE-ME-production/guest";
  guestLogStream = "guest";

  # Where the runtime fetches its guest: a key in `rootsBucket`, used verbatim
  # (`bucketPrefix` is not applied).
  #
  # The key is measured by PCR0 like everything else here. The object behind it
  # is measured by the enclave into PCR16 at boot, before it asks KMS for a key,
  # so it need not be trusted: changing the guest is an upload and a key-policy
  # edit, not a new image. Upload `guest-release/guest.wasm` here.
  guestObject = "guest/guest.wasm";

  # Opt in only for a guest implementing enclave:tasks/background@0.1.0.
  # Each task is authorized by an authenticated tenant interaction. Queued
  # work survives restarts; only this active enclave may own its scheduler.
  backgroundTasks = false;
  backgroundConcurrency = 1;
  # How long one background task may run. A task that drives a round with an
  # outside service waits on that service's schedule, which is minutes. `null`
  # keeps the runtime's default (30 seconds) and leaves PCR0 as it was.
  backgroundTimeoutSecs = null;

  # Origins guests may send requests to, as "https://host[:port]". None by
  # default, and then a guest has no outbound network at all.
  #
  # Compared exactly — scheme, host, port — over TLS verified against the web
  # PKI. It is a channel out of the enclave carrying whatever the guest puts in
  # it, so name only services the guest has to reach: for a wallet cosigner,
  # its ASP. Measured by PCR0 like everything here: a client learns where the
  # guest can send traffic from the attestation, and adding one is a new image.
  guestEgressOrigins = [ ];

  # Variables for the guest, as { NAME = "value"; }. The guest inherits the image
  # environment minus anything under `AWS_` or `S3FS_`, so these reach it — and,
  # being image environment, are measured by PCR0 like the rest. For a cosigner
  # whose egress names its ASP, this is where it learns the address: { ASP_URL =
  # "https://asp.example.com"; }.
  guestEnv = { };

  # Push notifications, off unless both are set. `fcmProjectId` is the Firebase
  # project; the service account itself is read at boot from this SSM parameter
  # rather than baked in, so it rotates without moving PCR0.
  #
  # What a parent that steals that credential gets is the ability to ring
  # doorbells: a wake signal carries no content, and reading anything still
  # needs a key KMS releases only against a matching PCR0 and PCR16.
  fcmProjectId = "";
  fcmServiceAccountParameter = "";
}
