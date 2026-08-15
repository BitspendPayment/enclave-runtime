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
# measurements. That is the same argument as baking the guest in rather than
# streaming it over vsock — the enclave's identity includes what it operates on.
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

  # Domains for the serving certificate. Empty means a self-signed one, which
  # a client verifying attestation accepts and a browser does not.
  tlsDomains = [ ];
}
