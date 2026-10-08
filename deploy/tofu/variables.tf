variable "region" {
  type    = string
  default = "eu-west-2"
}

# Named rather than left to the environment when this is used as a module: the
# module's provider is its own, so an unset AWS_PROFILE would otherwise put half
# a deployment in whichever account the default profile names.
variable "aws_profile" {
  type    = string
  default = null
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "name_prefix" {
  type    = string
  default = "enclave"
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

variable "roots_bucket" {
  type        = string
  description = <<-EOT
    The Object-Locked bucket: the pool's anchor chain, the boot records, the
    guest and the sealed ACME cache. Its COMPLIANCE retention is the entire
    rollback guarantee; the state itself is on the pool's disk. It must
    already exist — this deployment deliberately does not create it, because
    COMPLIANCE retention cannot be undone by anyone, including AWS support.
  EOT
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

variable "extra_ingress_ports" {
  type        = list(number)
  default     = []
  description = "TCP ports besides 443 to open, for services that run on the parent beside the enclave. They are not the enclave's: TLS to them terminates on the parent."
}

variable "guest_log_retention_days" {
  description = "How long to keep guest stdout/stderr. The contents are chosen by the guest, so this is a cost bound as much as a policy."
  type        = number
  default     = 30
}

variable "push_app_id" {
  description = "The AWS End User Messaging Push application wake signals go through, as the image names it (pushAppId), or empty for none. The parent's role may send through this one application."
  type        = string
  default     = ""
}

variable "pool_size_gib" {
  type        = number
  default     = 32
  description = "Size of the EBS volume holding the enclave's ZFS pool."
}
