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
}
