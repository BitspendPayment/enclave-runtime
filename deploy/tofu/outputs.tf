output "public_ip" {
  value       = aws_instance.parent.public_ip
  description = "Where the enclave answers on :443"
}

output "instance_id" {
  value = aws_instance.parent.id
}

# For a deployment that builds on this one rather than copying it: a KMS key
# policy names the role, more ports open on the group, a volume lands in the
# instance's zone, and the image's `guestLogGroup` must be this group.
output "role_arn" {
  value = aws_iam_role.parent.arn
}

output "role_name" {
  value = aws_iam_role.parent.name
}

output "security_group_id" {
  value = aws_security_group.enclave.id
}

output "availability_zone" {
  value = aws_instance.parent.availability_zone
}

output "guest_log_group" {
  value = aws_cloudwatch_log_group.guest.name
}

# What to run once it is up. The last command is the one that matters: it
# checks that the certificate the connection was served is the one the enclave
# attested, and that the runtime and guest behind it are the approved ones.
output "verify" {
  value = <<-EOT
    # Before the first start, and for every guest change: upload the guest the
    # key policy pins. The key must match `guestObject` in
    # deploy/nix/deployment.nix. The enclave measures what it fetches into
    # PCR16 and asks KMS for its key with that measurement, so an object the
    # policy does not name boots an enclave that can read nothing.
    nix build .#guest-release --out-link guest-release
    aws s3 cp guest-release/guest.wasm \
        s3://${length(var.buckets) > 1 ? var.buckets[1] : var.buckets[0]}/guest/guest.wasm

    # The key policy's condition, on both kms:GenerateDataKey and kms:Decrypt,
    # in a policy nobody can edit — the enclave refuses any other
    # (runtime/src/keys/policy.rs). It names one pair for good: a new runtime
    # or guest cannot open a store made under it.
    #   "kms:RecipientAttestation:PCR0":  "$(jq -r .PCR0 result/pcr.json)"
    #   "kms:RecipientAttestation:PCR16": "$(jq -r .PCR16 guest-release/guest-pcr16.json)"

    # Watch it come up (no SSH port is open; this uses SSM)
    aws ssm start-session --target ${aws_instance.parent.id}
    journalctl -u enclave.service -f

    # Verify from anywhere
    nitro-attest --url https://${aws_instance.parent.public_ip}/auth/ \
        --pcr0 "$(jq -r .PCR0 result/pcr.json)" \
        --guest guest-release/guest.wasm
  EOT
}
