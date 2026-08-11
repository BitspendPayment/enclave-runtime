# The AMI for the parent instance that hosts the enclave.
#
# Built with Packer over Amazon Linux 2023, not with Nix, and the split is not
# arbitrary: the parent is the party the enclave *excludes*. PCR0 covers what
# runs inside the enclave and says nothing about its host, so reproducing this
# machine buys no security property. AWS ships and supports the Nitro Enclaves
# CLI and allocator on AL2023, which is worth more here than a bit-identical
# image would be.
#
# The EIF is passed in rather than fetched, because *that* artifact is
# attested. It comes from `nix build .#eif`, which is reproducible, and baking
# it means the running enclave's PCR0 traces back to a build anyone can repeat.
#
#   nix build .#eif
#   nix build .#gvproxy
#   packer init deploy/ami
#   packer build \
#     -var eif=$(readlink -f result)/s3fs.eif \
#     -var pcr_json=$(readlink -f result)/pcr.json \
#     -var gvproxy=$(readlink -f result-1)/bin/gvproxy \
#     deploy/ami

packer {
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "instance_type" {
  type = string
  # Building needs no enclave support — only running does — so this is chosen
  # for build speed rather than from the enclave-capable list.
  default     = "c6i.large"
  description = "Instance type used to build the image"
}

variable "eif" {
  type        = string
  description = "Path to the EIF from `nix build .#eif`"
}

variable "pcr_json" {
  type        = string
  description = "Path to pcr.json from the same build, baked alongside the EIF"
}

variable "gvproxy" {
  type        = string
  description = "Path to the static gvproxy from `nix build .#gvproxy`"
}

variable "enclave_cpu_count" {
  type        = number
  default     = 2
  description = "vCPUs the allocator reserves for enclaves"
}

variable "enclave_memory_mib" {
  type = number
  # The EIF is ~140 MiB (a Nix closure, not a stripped musl binary) and the
  # enclave needs room for the image plus the runtime's own heap. The 512 MiB
  # default would fail at `run-enclave` with a message about memory that does
  # not mention the image size.
  default     = 3072
  description = "Memory the allocator reserves for enclaves, in MiB"
}

variable "ami_name_prefix" {
  type    = string
  default = "s3fs-enclave-parent"
}

locals {
  timestamp = regex_replace(timestamp(), "[- TZ:]", "")
}

source "amazon-ebs" "parent" {
  region        = var.region
  instance_type = var.instance_type
  ssh_username  = "ec2-user"

  ami_name        = "${var.ami_name_prefix}-${local.timestamp}"
  ami_description = "Nitro Enclaves parent: nitro-cli, gvproxy, and a pinned s3fs EIF"

  source_ami_filter {
    filters = {
      name                = "al2023-ami-2023.*-kernel-6.*-x86_64"
      virtualization-type = "hvm"
      root-device-type    = "ebs"
    }
    owners      = ["amazon"]
    most_recent = true
  }

  # The EIF alone is ~140 MiB; the default 8 GiB root leaves ample room but is
  # stated so a larger image does not silently fill the disk.
  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = 16
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name      = "${var.ami_name_prefix}-${local.timestamp}"
    Component = "nitro-enclave-parent"
  }
}

build {
  sources = ["source.amazon-ebs.parent"]

  # ---- the Nitro Enclaves CLI -------------------------------------------
  #
  # Deliberately no Docker. It is needed only by `nitro-cli build-enclave`,
  # and the image is built by Nix — so the untrusted host carries one fewer
  # daemon, and there is no path by which an image could be rebuilt here into
  # something with a different PCR0.
  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "sudo dnf -y update",
      "sudo dnf -y install aws-nitro-enclaves-cli jq",
      "sudo usermod -aG ne ec2-user",
      "nitro-cli --version",
    ]
  }

  # ---- the artifacts ------------------------------------------------------
  provisioner "shell" {
    inline = ["sudo mkdir -p /opt/enclave && sudo chown ec2-user /opt/enclave"]
  }

  provisioner "file" {
    source      = var.eif
    destination = "/opt/enclave/s3fs.eif"
  }

  # The measurements the image claims, kept next to it. This is what lets an
  # operator compare a running enclave's attested PCR0 against a rebuild —
  # without it, a reproducible build proves nothing to anybody on the box.
  provisioner "file" {
    source      = var.pcr_json
    destination = "/opt/enclave/pcr.json"
  }

  # The same pin as the gvforwarder inside the EIF: one nixpkgs package emits
  # both ends of the vsock, so they cannot drift apart. Static, because there
  # is no Nix store on this machine to link against.
  provisioner "file" {
    source      = var.gvproxy
    destination = "/opt/enclave/gvproxy"
  }

  # ---- allocator ----------------------------------------------------------
  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "sudo chmod +x /opt/enclave/gvproxy",
      "sudo install -m 0755 /opt/enclave/gvproxy /usr/local/bin/gvproxy",
      "sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null <<'YAML'",
      "---",
      "memory_mib: ${var.enclave_memory_mib}",
      "cpu_count: ${var.enclave_cpu_count}",
      "YAML",
      "sudo systemctl enable nitro-enclaves-allocator.service",
    ]
  }

  # ---- systemd ------------------------------------------------------------
  provisioner "file" {
    source      = "${path.root}/units/"
    destination = "/tmp/units"
  }

  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "sudo install -m 0644 /tmp/units/gvproxy.service /etc/systemd/system/",
      "sudo install -m 0644 /tmp/units/enclave.service /etc/systemd/system/",
      "sudo install -m 0755 /tmp/units/enclave-start.sh /usr/local/bin/enclave-start",
      "sudo systemctl enable gvproxy.service enclave.service",
      # Fail the build rather than the boot: a unit that will not even parse is
      # discovered here, not at 3am on a machine with no shell access.
      "sudo systemd-analyze verify /etc/systemd/system/gvproxy.service",
      "sudo systemd-analyze verify /etc/systemd/system/enclave.service",
    ]
  }

  post-processor "manifest" {
    output     = "deploy/ami/manifest.json"
    strip_path = true
  }
}
