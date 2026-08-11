output "public_ip" {
  value       = aws_instance.parent.public_ip
  description = "Where the enclave answers on :443"
}

output "instance_id" {
  value = aws_instance.parent.id
}

# What to run once it is up. The last command is the one that matters: it
# checks that the certificate the connection was served is the one the enclave
# attested, which is the property the whole design exists for.
output "verify" {
  value = <<-EOT
    # Watch it come up (no SSH port is open; this uses SSM)
    aws ssm start-session --target ${aws_instance.parent.id}
    journalctl -u enclave.service -f

    # Verify from anywhere
    nitro-attest --url https://${aws_instance.parent.public_ip}/enclave/attestation \
        --pcr0 "$(jq -r .PCR0 result/pcr.json)" \
        --guest result/guest.wasm
  EOT
}
