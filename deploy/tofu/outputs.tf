output "public_ip" {
  value       = aws_instance.parent.public_ip
  description = "Where the enclave answers on :443"
}

output "instance_id" {
  value = aws_instance.parent.id
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

    # The key policy's condition, on both kms:GenerateDataKey and kms:Decrypt.
    # Replace PCR16 on a guest change; never add a second value beside it.
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
