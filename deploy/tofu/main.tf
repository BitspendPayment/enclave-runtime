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
  region  = var.region
  profile = var.aws_profile
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

  # Services that share the parent and are no part of the enclave — they see
  # only what reaches them, like anything else on the parent.
  dynamic "ingress" {
    for_each = var.extra_ingress_ports
    content {
      description = "Beside the enclave, on the parent"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = var.ingress_cidrs
    }
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
      # Root records are read by version, underneath any delete marker.
      "s3:ListBucketVersions",
      "s3:GetObjectVersion",
      # A PutObject that carries retention headers needs this too.
      "s3:PutObjectRetention",
    ]
    resources = concat(
      ["arn:aws:s3:::${var.roots_bucket}"],
      ["arn:aws:s3:::${var.roots_bucket}/*"],
    )
  }

  # The anchor chain is what makes rollback detectable, and Object Lock is what
  # makes it immutable. Nothing on the parent has any business relaxing that,
  # so the permission to do it is withheld rather than merely unused.
  # PutObjectRetention is not in this list because the runtime needs it to
  # write roots at all, and in COMPLIANCE mode it can only extend a retention,
  # never shorten one.
  statement {
    sid    = "NeverWeakenRetention"
    effect = "Deny"
    actions = [
      "s3:PutBucketObjectLockConfiguration",
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

# ---------------------------------------------------------------------------
# Guest logs
# ---------------------------------------------------------------------------

# For building log ARNs by hand — see the policy below.
data "aws_caller_identity" "current" {}

# Created here, not by the enclave. The enclave holds `logs:PutLogEvents` and
# nothing more, so a compromised or misconfigured image cannot create log
# groups — and a typo in the group name fails its boot loudly instead of
# quietly filling a new group nobody is watching.
resource "aws_cloudwatch_log_group" "guest" {
  name = "/${local.name}/guest"

  # Set deliberately. Left unset these never expire, and the contents are
  # attacker-controlled: whatever a guest chose to write to stdout. An
  # unbounded retention on unbounded input is an unbounded bill.
  retention_in_days = var.guest_log_retention_days

  tags = local.tags
}

resource "aws_cloudwatch_log_stream" "guest" {
  name           = "guest"
  log_group_name = aws_cloudwatch_log_group.guest.name
}

# This is the **parent instance's** role, and it is the identity that will make
# the call. The enclave is not an IAM principal and has none of its own: it has
# no NIC, so its SDK reaches IMDS through gvproxy on this instance and receives
# these credentials. When the enclave gets an attested identity of its own,
# this statement moves there and the parent stops being able to write to the
# stream at all.
data "aws_iam_policy_document" "guest_logs" {
  statement {
    sid     = "WriteGuestLogs"
    effect  = "Allow"
    actions = ["logs:PutLogEvents"]
    # The one stream, not the group and not `*`. Nothing here needs to create
    # a group, a stream, or write to anyone else's.
    #
    # Built from components rather than from `aws_cloudwatch_log_group.arn`,
    # which is inconsistent about carrying a trailing `:*`. Appending to it
    # would silently produce an ARN matching nothing — and the symptom is an
    # `AccessDeniedException`, which this runtime treats as a deployment
    # mistake and refuses to boot on. Worth the extra interpolation.
    resources = [
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.guest.name}:log-stream:${aws_cloudwatch_log_stream.guest.name}",
    ]
  }
}

resource "aws_iam_role_policy" "guest_logs" {
  name   = "${local.name}-guest-logs"
  role   = aws_iam_role.parent.id
  policy = data.aws_iam_policy_document.guest_logs.json
}

# Wake signals, through the one push application the image names (`pushAppId` in
# deploy/nix/deployment.nix) and nothing else: sending, and reading its FCM channel, which the
# runtime does once at boot to refuse an application that could never deliver. The Firebase
# credential lives on that channel, not here and not in the image. None without an application.
data "aws_iam_policy_document" "push" {
  count = var.push_app_id == "" ? 0 : 1
  statement {
    sid     = "SendWakes"
    effect  = "Allow"
    actions = ["mobiletargeting:SendMessages", "mobiletargeting:GetGcmChannel"]
    resources = [
      "arn:aws:mobiletargeting:${var.region}:${data.aws_caller_identity.current.account_id}:apps/${var.push_app_id}",
      "arn:aws:mobiletargeting:${var.region}:${data.aws_caller_identity.current.account_id}:apps/${var.push_app_id}/*",
    ]
  }
}

resource "aws_iam_role_policy" "push" {
  count  = var.push_app_id == "" ? 0 : 1
  name   = "${local.name}-push"
  role   = aws_iam_role.parent.id
  policy = data.aws_iam_policy_document.push[0].json
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

    # UNVERIFIED ON HARDWARE. The enclave reaches IMDS only at 192.168.127.253,
    # which gvproxy maps to 169.254.169.254 (deploy/ami/units/gvproxy.yml) and
    # the image names in AWS_EC2_METADATA_SERVICE_ENDPOINT; no guest can reach
    # it. Every AWS call the enclave makes rests on that path, and the QEMU
    # harness has no metadata service to prove it with. The push probe at boot
    # is the first check that it works.
    #
    # One hop is right: gvproxy proxies rather than routes — it terminates the
    # enclave's connection here and dials its own (pkg/services/forwarder/tcp.go),
    # so the request originates on this instance. Stated rather than defaulted,
    # because the value is a deployment decision and not an incidental.
    http_put_response_hop_limit = 1
  }

  # Which device is the pool's disk: the one thing the parent needs that the
  # image cannot know. The enclave's settings are in the image, measured.
  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    # How the volume appears to the parent: NVMe, named by its id.
    pool_disk = "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${replace(aws_ebs_volume.pool.id, "-", "")}"
  })

  user_data_replace_on_change = true

  tags = local.tags
}

# ---------------------------------------------------------------------------
# The pool's disk
# ---------------------------------------------------------------------------

# Where everything the enclave keeps lives: a ZFS pool on dm-crypt, served to
# the enclave by nbdkit on the parent (deploy/ami/units/nbdkit.service). The
# parent sees only ciphertext; the anchor chain in the roots bucket is what
# makes a rolled-back or substituted volume refused at boot — restoring an
# older snapshot of this volume is exactly that, and the enclave will not
# serve it.
#
# Never destroyed by a plan: this volume *is* the state. Losing it leaves
# anchors no disk can satisfy, and the enclave refuses to start rather than
# begin again.
resource "aws_ebs_volume" "pool" {
  availability_zone = aws_subnet.public.availability_zone
  size              = var.pool_size_gib
  type              = "gp3"
  # Amazon's at-rest encryption, beneath the enclave's own dm-crypt.
  encrypted = true

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.tags, { Name = "${local.name}-pool" })
}

resource "aws_volume_attachment" "pool" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.pool.id
  instance_id = aws_instance.parent.id
}
