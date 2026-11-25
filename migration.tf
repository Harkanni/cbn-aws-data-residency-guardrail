# ---------------------------------------------------------------------------
# migration.tf - a REAL cross-region migration scenario. Lives next to main.tf.
#
#   LEGACY region (default eu-west-1, offshore)        APPROVED region (af-south-1)
#   - EC2 server, stopped, with an AMI            -->  copied AMI (re-encrypted with our KMS key) and a new instance
#   - DynamoDB table with 30 SIMULATED payments   -->  KMS-encrypted DynamoDB table
#
# The migration is run from the local console by a dedicated "migrator" role whose policy says:
# reads from the legacy region are allowed, every other action must target the approved region.
# So data can move IN, but any attempt to move it OUT (or to write anywhere else) is denied.
# After the copy is verified, the console can DECOMMISSION the offshore originals (delete the table,
# terminate the server, deregister its image, delete the snapshot), as the CBN FAQ expects: no copies
# left abroad. Terraform recreates the legacy side on the next apply, so ./deploy.sh fix replays the demo.
# The migration itself (copy image, launch instance, copy records) is created at run time by the
# console, not by Terraform. Click Reset in the console before `./deploy.sh destroy`.
#
# Cost: one t3.micro stopped in the legacy region (disk and AMI storage only), a few cents for the
# snapshot, and a t3.micro running in af-south-1 while you demo. Pay-per-request DynamoDB is pennies.
# ---------------------------------------------------------------------------

variable "legacy_region" {
  description = "Offshore region that holds the legacy workload to migrate from."
  type        = string
  default     = "eu-west-1"
}

provider "aws" {
  alias  = "legacy"
  region = var.legacy_region
}

# ------------------------------ Legacy side --------------------------------

resource "aws_dynamodb_table" "legacy" {
  provider     = aws.legacy
  name         = "${var.name_prefix}-legacy-payments"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "payment_id"

  attribute {
    name = "payment_id"
    type = "S"
  }
}

resource "aws_dynamodb_table_item" "legacy" {
  provider   = aws.legacy
  for_each   = toset([for i in range(1, 31) : format("PAY-%04d", i)])
  table_name = aws_dynamodb_table.legacy.name
  hash_key   = aws_dynamodb_table.legacy.hash_key

  item = jsonencode({
    payment_id = { S = each.key }
    amount     = { N = tostring(1000 + tonumber(substr(each.key, 4, 4)) * 250) }
    currency   = { S = "NGN" }
    note       = { S = "SIMULATED DATA" }
  })
}

data "aws_ssm_parameter" "al2023_legacy" {
  provider = aws.legacy
  name     = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_instance" "legacy" {
  provider      = aws.legacy
  ami           = data.aws_ssm_parameter.al2023_legacy.value
  instance_type = "t3.micro"

  tags = { Name = "${var.name_prefix}-legacy-payments-app" }
}

resource "aws_ami_from_instance" "legacy" {
  provider                = aws.legacy
  name                    = "${var.name_prefix}-legacy-payments-app"
  source_instance_id      = aws_instance.legacy.id
  snapshot_without_reboot = true

  tags = { Name = "${var.name_prefix}-legacy-payments-app" }
}

# Stop the legacy server once its image exists, so it only costs disk storage.
resource "aws_ec2_instance_state" "legacy_stopped" {
  provider    = aws.legacy
  instance_id = aws_instance.legacy.id
  state       = "stopped"
  depends_on  = [aws_ami_from_instance.legacy]
}

# ----------------------------- Approved side -------------------------------

# Empty at first; the migration fills it. Encrypted at rest with the bank's own KMS key.
resource "aws_dynamodb_table" "migrated" {
  name         = "${var.name_prefix}-migrated-payments"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "payment_id"

  attribute {
    name = "payment_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.payments.arn
  }
}

# --------------------------- Inbound-only migrator --------------------------

# Inbound-only migration, in two explicit denies (explicit denies beat AdministratorAccess):
#   1. Outside the approved AND legacy regions, nothing at all (global services aside).
#   2. In the legacy region: reads, so data can be copied IN, plus four delete-only actions so the
#      offshore originals can be decommissioned after the copy is verified. Nothing that writes data
#      offshore is allowed (no PutItem, BatchWriteItem, CopyImage or CreateSnapshot), so data cannot leave.
locals {
  global_not_actions = jsondecode(aws_iam_policy.region_lock.policy).Statement[0].NotAction
  legacy_reads = ["dynamodb:Scan", "dynamodb:Query", "dynamodb:GetItem", "dynamodb:DescribeTable",
  "ec2:DescribeImages", "ec2:DescribeSnapshots", "ec2:DescribeInstances"]
  legacy_decommission = ["dynamodb:DeleteTable", "ec2:TerminateInstances", "ec2:DeregisterImage", "ec2:DeleteSnapshot"]
}

resource "aws_iam_policy" "inbound_only" {
  name        = "${var.name_prefix}-inbound-only-migration"
  description = "Writes only in ${var.approved_region}; in ${var.legacy_region} only reads and decommission deletes"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyAllOutsideApprovedAndLegacyRegions"
        Effect    = "Deny"
        NotAction = local.global_not_actions
        Resource  = "*"
        Condition = { StringNotEquals = { "aws:RequestedRegion" = [var.approved_region, var.legacy_region] } }
      },
      {
        Sid       = "LegacyRegionReadAndDecommissionOnly"
        Effect    = "Deny"
        NotAction = concat(local.global_not_actions, local.legacy_reads, local.legacy_decommission)
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = var.legacy_region } }
      }
    ]
  })
}

resource "aws_iam_role" "migrator" {
  name = "${var.name_prefix}-migrator"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "migrator_admin" {
  role       = aws_iam_role.migrator.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy_attachment" "migrator_inbound_only" {
  role       = aws_iam_role.migrator.name
  policy_arn = aws_iam_policy.inbound_only.arn
}

resource "aws_iam_role_policy_attachment" "migrator_no_replication" {
  role       = aws_iam_role.migrator.name
  policy_arn = aws_iam_policy.no_replication.arn
}

# ------------------------------- Outputs -----------------------------------

output "mig_legacy_region" {
  value = var.legacy_region
}

output "mig_legacy_table" {
  value = aws_dynamodb_table.legacy.name
}

output "mig_dest_table" {
  value = aws_dynamodb_table.migrated.name
}

output "mig_legacy_ami" {
  value = aws_ami_from_instance.legacy.id
}

output "mig_legacy_instance" {
  value = aws_instance.legacy.id
}
