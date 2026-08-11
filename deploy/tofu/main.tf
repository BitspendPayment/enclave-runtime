# The parent instance that hosts the enclave.
#
# What this brings up is deliberately the *untrusted* half: a machine, a
# network path to it, and permission to read the buckets. The enclave's
# identity comes from PCR0, which is a property of the image rather than of
# anything declared here — so nothing in this file needs to be trusted for the
# attestation argument to hold, and none of it is a place to put a secret.
#
#   nix build .#eif && packer build … deploy/ami     # → ami-…
#   tofu init && tofu apply -var ami_id=ami-…
#
# Storage is out of scope on purpose. The roots bucket carries Object Lock
# COMPLIANCE retention, which cannot be shortened or removed by anyone,
# including AWS support; creating that from a general-purpose deployment is a
# way to lose a bucket for ten years by typo. Point this at buckets that
# already exist.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  name = "${var.name_prefix}-${var.environment}"

  tags = {
    Name        = local.name
    Environment = var.environment
    Component   = "nitro-enclave-parent"
    ManagedBy   = "opentofu"
  }
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = local.tags
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true
  tags                    = local.tags
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = local.tags
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------------
# Access
# ---------------------------------------------------------------------------

resource "aws_security_group" "enclave" {
  name        = "${local.name}-enclave"
  description = "Inbound HTTPS to the enclave; egress for S3, KMS and ACME"
  vpc_id      = aws_vpc.this.id
  tags        = local.tags

  # TLS terminates *inside* the enclave, so what passes through here is
  # ciphertext the parent cannot read. This rule admits traffic to the machine;
  # it does not grant the machine sight of it.
  ingress {
    description = "HTTPS, terminated inside the enclave"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidrs
  }

  # No SSH. Nothing here is meant to be reached by hand, and an open shell on
  # the parent is the most useful thing an attacker could be given — it is the
  # machine that proxies every byte in and out of the enclave. Use SSM if a
  # session is genuinely needed.
  egress {
    description = "Outbound for S3, KMS and the ACME provider"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

resource "aws_iam_role" "parent" {
  name = "${local.name}-parent"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# The parent proxies the enclave's S3 traffic, so its role is what reaches the
# buckets. That is not a hole in the design: the objects are encrypted under
# keys derived from a master secret the parent does not hold, so this grants
# the ability to serve and delete ciphertext, not to read it.
data "aws_iam_policy_document" "buckets" {
  statement {
    sid    = "ReadWriteObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = concat(
      [for b in var.buckets : "arn:aws:s3:::${b}"],
      [for b in var.buckets : "arn:aws:s3:::${b}/*"],
    )
  }

  # The anchor chain is what makes rollback detectable, and Object Lock is what
  # makes it immutable. Nothing on the parent has any business relaxing that,
  # so the permission to do it is withheld rather than merely unused.
  statement {
    sid    = "NeverWeakenRetention"
    effect = "Deny"
    actions = [
      "s3:PutBucketObjectLockConfiguration",
      "s3:PutObjectRetention",
      "s3:PutObjectLegalHold",
      "s3:BypassGovernanceRetention",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "buckets" {
  name   = "${local.name}-buckets"
  role   = aws_iam_role.parent.id
  policy = data.aws_iam_policy_document.buckets.json
}

# For a shell without opening port 22.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.parent.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "parent" {
  name = "${local.name}-parent"
  role = aws_iam_role.parent.name
  tags = local.tags
}

# ---------------------------------------------------------------------------
# The instance
# ---------------------------------------------------------------------------

resource "aws_instance" "parent" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.enclave.id]
  iam_instance_profile   = aws_iam_instance_profile.parent.name

  # The whole point of the machine. Without it `nitro-cli run-enclave` fails
  # with a message about the driver rather than about this flag.
  enclave_options {
    enabled = true
  }

  # Nitro Enclaves needs at least 4 vCPUs, because the allocator reserves whole
  # cores for the enclave and the parent still has to run. Smaller types are
  # accepted by the API and then cannot start an enclave.
  lifecycle {
    precondition {
      condition     = can(regex("\\.(x|2x|4x|8x|12x|16x|24x|metal)large$", var.instance_type)) || can(regex("\\.xlarge$", var.instance_type))
      error_message = "instance_type must be enclave-capable with >= 4 vCPUs (xlarge or bigger)."
    }
  }

  root_block_device {
    volume_size = 32
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2
    http_endpoint = "enabled"
  }

  # Configuration the image cannot know: which buckets, and which domain the
  # certificate is for. Not secrets — the master key is not passed here, and
  # once M8 lands it comes from KMS gated on PCR0 rather than from anywhere on
  # this machine.
  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    data_bucket  = var.buckets[0]
    roots_bucket = length(var.buckets) > 1 ? var.buckets[1] : var.buckets[0]
    region       = var.region
    tls_domains  = join(",", var.tls_domains)
  })

  user_data_replace_on_change = true

  tags = local.tags
}
