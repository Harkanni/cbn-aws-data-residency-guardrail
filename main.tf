# ---------------------------------------------------------------------------
# Region-Lock Guardrail Demo - SINGLE-ACCOUNT version (no AWS Organizations needed)
#
# What this builds, all inside one standard AWS account
#   IAM       : a "guardrail operator" role = AdministratorAccess + two explicit-deny policies
#               (1) deny every action outside the approved region
#               (2) deny S3 replication, multi-Region access points and multi-Region KMS keys
#               The role cannot detach, edit or delete its own guardrails.
#   KMS       : single-Region customer managed key, rotation on
#   S3        : private, versioned "payments" bucket; bucket policy enforces TLS, KMS-only
#               uploads with OUR key, and denies replication changes for EVERY identity
#   Config    : recorder + 4 managed rules
#   Alerts    : SNS email + EventBridge rules (replication change, Config NON_COMPLIANT)
#   Audit     : CloudTrail trail (needed for EventBridge to see API calls; also the audit log)
#
# Be clear about the limits (say this in your case study)
#   - IAM policies only bind the identities they are attached to. The region lock binds the
#     operator role; your root user and other admins are NOT constrained by it. A true
#     account-wide region lock needs AWS Organizations SCPs (see main-with-organizations.tf.txt).
#   - The bucket policy sits on the resource, so it binds every identity, admins included.
#   - af-south-1 (Cape Town) is NOT inside Nigeria. This shows a guardrail pattern, not
#     CBN compliance. Change var.approved_region to re-point it.
#
# Prerequisites
#   1. One AWS account and an IAM admin user or role. Do NOT use the root user: root cannot
#      assume roles, which the tests need.
#   2. The approved region is enabled in the account (opt-in region; wait until Enabled).
#   3. No existing AWS Config recorder in the approved region (one per region is allowed).
#
# Usage
#   terraform init
#   terraform apply -var alert_email=you@example.com
#   Then CONFIRM the subscription email AWS sends, or no alerts will arrive.
#
# Cost: KMS key ~$1/month, Config bills per recorded item. Run `terraform destroy` when done
# (the KMS key has a 7-day deletion window).
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

# ------------------------------- Variables ---------------------------------

variable "approved_region" {
  description = "The only region the guardrail operator role may use."
  type        = string
  default     = "af-south-1"
}

variable "alert_email" {
  description = "Email address that receives guardrail alerts."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names (lowercase letters, digits, hyphens)."
  type        = string
  default     = "region-lock-demo"
}

# ------------------------------- Provider ----------------------------------

provider "aws" {
  region = var.approved_region
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  payments_bucket_name = "${var.name_prefix}-payments-${local.account_id}"
  config_bucket_name   = "${var.name_prefix}-config-${local.account_id}"
  trail_bucket_name    = "${var.name_prefix}-trail-${local.account_id}"

  trail_name = "${var.name_prefix}-audit"
  trail_arn  = "arn:aws:cloudtrail:${var.approved_region}:${local.account_id}:trail/${local.trail_name}"
}

# ===========================================================================
# 1. IAM GUARDRAIL OPERATOR ROLE
# ===========================================================================

# Policy 1: deny any action outside the approved region (AWS's sample region-deny pattern;
# global services are exempted via NotAction). kms:* and config:* are NOT exempted.
resource "aws_iam_policy" "region_lock" {
  name        = "${var.name_prefix}-deny-outside-approved-region"
  description = "Deny all actions outside ${var.approved_region} except global services"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyAllOutsideApprovedRegion"
        Effect = "Deny"
        NotAction = [
          "a4b:*", "acm:*", "aws-marketplace-management:*", "aws-marketplace:*",
          "aws-portal:*", "budgets:*", "ce:*", "chime:*", "cloudfront:*", "cur:*",
          "directconnect:*", "ec2:DescribeRegions", "ec2:DescribeTransitGateways",
          "ec2:DescribeVpnGateways", "fms:*", "globalaccelerator:*", "health:*",
          "iam:*", "importexport:*", "mobileanalytics:*", "networkmanager:*",
          "organizations:*", "pricing:*", "route53:*", "route53domains:*",
          "s3:GetAccountPublic*", "s3:ListAllMyBuckets", "s3:PutAccountPublic*",
          "shield:*", "sts:*", "support:*", "trustedadvisor:*",
          "waf-regional:*", "waf:*", "wafv2:*", "wellarchitected:*"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = [var.approved_region]
          }
        }
      }
    ]
  })
}

# Policy 2: block the main routes for moving data across regions.
resource "aws_iam_policy" "no_replication" {
  name        = "${var.name_prefix}-deny-replication-and-multiregion"
  description = "Deny S3 replication, S3 multi-Region access points and multi-Region KMS keys"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyS3ReplicationAndMultiRegionAccessPoints"
        Effect = "Deny"
        Action = [
          "s3:PutReplicationConfiguration",
          "s3:CreateMultiRegionAccessPoint"
        ]
        Resource = "*"
      },
      {
        Sid      = "DenyMultiRegionKmsKeys"
        Effect   = "Deny"
        Action   = ["kms:CreateKey", "kms:ReplicateKey"]
        Resource = "*"
        Condition = {
          Bool = { "kms:MultiRegion" = "true" }
        }
      }
    ]
  })
}

# Any IAM principal in this account that is allowed to call sts:AssumeRole can use it.
resource "aws_iam_role" "operator" {
  name = "${var.name_prefix}-operator"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "operator_admin" {
  role       = aws_iam_role.operator.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy_attachment" "operator_region_lock" {
  role       = aws_iam_role.operator.name
  policy_arn = aws_iam_policy.region_lock.arn
}

resource "aws_iam_role_policy_attachment" "operator_no_replication" {
  role       = aws_iam_role.operator.name
  policy_arn = aws_iam_policy.no_replication.arn
}

# The role cannot remove or weaken its own guardrails.
resource "aws_iam_role_policy" "protect_guardrails" {
  name = "protect-guardrails"
  role = aws_iam_role.operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyEditingTheRole"
        Effect = "Deny"
        Action = [
          "iam:DetachRolePolicy", "iam:DeleteRolePolicy", "iam:PutRolePolicy",
          "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary",
          "iam:UpdateAssumeRolePolicy", "iam:DeleteRole"
        ]
        Resource = aws_iam_role.operator.arn
      },
      {
        Sid    = "DenyEditingTheGuardrailPolicies"
        Effect = "Deny"
        Action = [
          "iam:CreatePolicyVersion", "iam:DeletePolicyVersion",
          "iam:SetDefaultPolicyVersion", "iam:DeletePolicy"
        ]
        Resource = [aws_iam_policy.region_lock.arn, aws_iam_policy.no_replication.arn]
      }
    ]
  })
}

# ===========================================================================
# 2. KMS CUSTOMER MANAGED KEY
# ===========================================================================

resource "aws_kms_key" "payments" {
  description             = "CMK for the simulated payments bucket (single-Region)"
  enable_key_rotation     = true
  multi_region            = false # key material stays in ${var.approved_region}
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMPolicies"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "payments" {
  name          = "alias/${var.name_prefix}-payments"
  target_key_id = aws_kms_key.payments.key_id
}

# ===========================================================================
# 3. S3 PAYMENTS BUCKET
# ===========================================================================

resource "aws_s3_bucket" "payments" {
  bucket        = local.payments_bucket_name
  force_destroy = true # demo only
}

resource "aws_s3_bucket_public_access_block" "payments" {
  bucket                  = aws_s3_bucket.payments.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "payments" {
  bucket = aws_s3_bucket.payments.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "payments" {
  bucket = aws_s3_bucket.payments.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.payments.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "payments" {
  bucket = aws_s3_bucket.payments.id

  # Applied after the public-access block to avoid concurrent-modification errors.
  depends_on = [aws_s3_bucket_public_access_block.payments]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Binds EVERY identity, admins included, because it sits on the resource.
        Sid       = "DenyReplicationChanges"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutReplicationConfiguration"
        Resource  = aws_s3_bucket.payments.arn
      },
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.payments.arn,
          "${aws_s3_bucket.payments.arn}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        # If a request states an encryption type, it must be KMS.
        Sid       = "DenyNonKmsEncryption"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.payments.arn}/*"
        Condition = {
          StringNotEqualsIfExists = { "s3:x-amz-server-side-encryption" = "aws:kms" }
        }
      },
      {
        # If a request names a KMS key, it must be OUR key. (Requests naming no key fall
        # through to the bucket default, which is our key.)
        Sid       = "DenyWrongKmsKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.payments.arn}/*"
        Condition = {
          StringNotEqualsIfExists = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.payments.arn
          }
        }
      }
    ]
  })
}

# A fake receipt so the screenshot of "encrypted with our own key" has something to show.
resource "aws_s3_object" "sample_receipt" {
  bucket                 = aws_s3_bucket.payments.id
  key                    = "receipts/receipt-001.json"
  content_type           = "application/json"
  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.payments.arn

  content = jsonencode({
    receipt_id = "receipt-001"
    amount     = 15000
    currency   = "NGN"
    note       = "SIMULATED DATA - not a real transaction"
  })

  depends_on = [aws_s3_bucket_policy.payments]
}

# ===========================================================================
# 4. ALERTING: SNS + EVENTBRIDGE
# ===========================================================================

resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-guardrail-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email # you must click the confirmation link in your inbox
}

# Fires on ANY attempt to change bucket replication (CloudTrail management event).
# Matches regardless of errorCode, so a denied attempt should still alert; verify in
# CloudTrail event history if it does not arrive.
resource "aws_cloudwatch_event_rule" "replication_change" {
  name        = "${var.name_prefix}-replication-change"
  description = "Alert when S3 bucket replication is changed or attempted"

  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutBucketReplication"]
    }
  })
}

# Fires when any Config rule evaluates a resource as NON_COMPLIANT.
resource "aws_cloudwatch_event_rule" "config_noncompliant" {
  name        = "${var.name_prefix}-config-noncompliant"
  description = "Alert when an AWS Config rule reports NON_COMPLIANT"

  event_pattern = jsonencode({
    source        = ["aws.config"]
    "detail-type" = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "replication_to_sns" {
  rule = aws_cloudwatch_event_rule.replication_change.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_cloudwatch_event_target" "config_to_sns" {
  rule = aws_cloudwatch_event_rule.config_noncompliant.name
  arn  = aws_sns_topic.alerts.arn
}

# EventBridge only receives "AWS API Call via CloudTrail" events while a trail is logging, so
# without this trail the replication_change rule above never fires. Single-Region trail in the
# approved region; it also gives a durable audit log of every management call, denied ones included.
resource "aws_s3_bucket" "trail_logs" {
  bucket        = local.trail_bucket_name
  force_destroy = true # demo only
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket                  = aws_s3_bucket.trail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket     = aws_s3_bucket.trail_logs.id
  depends_on = [aws_s3_bucket_public_access_block.trail_logs]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail_logs.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail_logs.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      },
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.trail_logs.arn,
          "${aws_s3_bucket.trail_logs.arn}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

resource "aws_cloudtrail" "audit" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  is_multi_region_trail         = false
  include_global_service_events = false
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail_logs]
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      }
    ]
  })
}

# ===========================================================================
# 5. AWS CONFIG
# ===========================================================================

resource "aws_s3_bucket" "config_logs" {
  bucket        = local.config_bucket_name
  force_destroy = true # demo only
}

resource "aws_s3_bucket_public_access_block" "config_logs" {
  bucket                  = aws_s3_bucket.config_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config_logs" {
  bucket     = aws_s3_bucket.config_logs.id
  depends_on = [aws_s3_bucket_public_access_block.config_logs]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.config_logs.arn
        Condition = { StringEquals = { "AWS:SourceAccount" = local.account_id } }
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config_logs.arn}/AWSLogs/${local.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "AWS:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.config_logs.arn,
          "${aws_s3_bucket.config_logs.arn}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

resource "aws_iam_role" "config" {
  name = "${var.name_prefix}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_delivery" {
  name = "config-s3-delivery"
  role = aws_iam_role.config.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectAcl", "s3:GetBucketAcl"]
        Resource = [aws_s3_bucket.config_logs.arn, "${aws_s3_bucket.config_logs.arn}/*"]
      }
    ]
  })
}

resource "aws_config_configuration_recorder" "this" {
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported = true
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "${var.name_prefix}-channel"
  s3_bucket_name = aws_s3_bucket.config_logs.bucket

  depends_on = [
    aws_config_configuration_recorder.this,
    aws_s3_bucket_policy.config_logs,
    aws_iam_role_policy.config_delivery
  ]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

# --- Managed rules. The three S3 rules are scoped to the payments bucket only, so the
# --- Config log bucket (which uses default SSE-S3) does not show up as NON_COMPLIANT.

resource "aws_config_config_rule" "s3_kms_default_encryption" {
  name = "${var.name_prefix}-s3-default-encryption-kms"

  source {
    owner             = "AWS"
    source_identifier = "S3_DEFAULT_ENCRYPTION_KMS"
  }

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
    compliance_resource_id    = aws_s3_bucket.payments.id
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

resource "aws_config_config_rule" "s3_ssl_only" {
  name = "${var.name_prefix}-s3-ssl-requests-only"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
    compliance_resource_id    = aws_s3_bucket.payments.id
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

resource "aws_config_config_rule" "s3_no_public" {
  name = "${var.name_prefix}-s3-public-access-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
    compliance_resource_id    = aws_s3_bucket.payments.id
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

resource "aws_config_config_rule" "kms_rotation" {
  name = "${var.name_prefix}-cmk-rotation-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

# ------------------------------- Outputs -----------------------------------

output "payments_bucket" {
  value = aws_s3_bucket.payments.bucket
}

output "kms_key_arn" {
  value = aws_kms_key.payments.arn
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "guardrail_role_arn" {
  value = aws_iam_role.operator.arn
}

output "reminder" {
  value = "Confirm the SNS subscription email, then run ./deploy.sh test (denials as the operator role, replication denied for admins too) and ./deploy.sh drift (Config NON_COMPLIANT + alert)."
}
