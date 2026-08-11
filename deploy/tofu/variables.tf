variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "name_prefix" {
  type    = string
  default = "s3fs-enclave"
}

variable "ami_id" {
  type        = string
  description = "AMI from `packer build deploy/ami` — carries nitro-cli, gvproxy and the EIF"

  validation {
    condition     = can(regex("^ami-[0-9a-f]{8,}$", var.ami_id))
    error_message = "ami_id must look like ami-0123456789abcdef0."
  }
}

variable "instance_type" {
  type = string
  # Nitro Enclaves needs at least 4 vCPUs: the allocator reserves whole cores
  # for the enclave and the parent still has to run. m5.xlarge is the smallest
  # generally-available type that works.
  default     = "m5.xlarge"
  description = "Enclave-capable instance type with >= 4 vCPUs"
}

variable "buckets" {
  type        = list(string)
  description = <<-EOT
    [data_bucket, roots_bucket]. They should differ: the roots bucket carries
    Object Lock COMPLIANCE retention and is the entire rollback guarantee,
    while the data bucket stays unlocked so dead copy-on-write blocks remain
    reclaimable. Both must already exist — this deployment deliberately does
    not create them, because COMPLIANCE retention cannot be undone by anyone,
    including AWS support.
  EOT

  validation {
    condition     = length(var.buckets) >= 1 && length(var.buckets) <= 2
    error_message = "Give one bucket, or two as [data, roots]."
  }
}

variable "tls_domains" {
  type        = list(string)
  default     = []
  description = "Domains for the enclave's certificate. Required for ACME; a self-signed certificate needs none, since attestation rather than a CA is what a client checks."
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

variable "subnet_cidr" {
  type    = string
  default = "10.42.1.0/24"
}

variable "availability_zone" {
  type        = string
  default     = null
  description = "Defaults to the first AZ in the region."
}

variable "ingress_cidrs" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "Who may reach :443. Open by default because the endpoint is meant to be public and its TLS terminates inside the enclave."
}
