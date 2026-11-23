# ---------------------------------------------------------------------------
# hosting.tf - public live link for the guardrail console. Lives next to main.tf.
#
#   Browser --HTTPS--> CloudFront --/        --> private S3 bucket (the page, via OAC)
#                                 \--/api/*  --> API Gateway --> Lambda --> REAL AWS API calls
#
# The Lambda runs as a dedicated role that has the region-lock and no-replication deny policies
# attached, so every result is a real AWS authorization decision. Only fixed, whitelisted actions
# exist: no drift buttons, no admin actions, no user-supplied commands. API Gateway throttles to
# 5 requests/second and the handler adds its own per-minute cap.
#
# Delete this file (and run terraform apply) to remove the public site. Anyone with the link can
# trigger the whitelisted calls on your account, so set an AWS Budget alert and take the site
# down when you are not demoing. CloudFront serves only the static page; no payment data passes
# through it. A new account may need CloudFront verification before the distribution can be created.
# ---------------------------------------------------------------------------



variable "api_token" {
  description = "Optional shared token for the public console. Empty keeps the demo open; when set, open the site as https://<site>/?t=<token>."
  type        = string
  default     = ""
  sensitive   = true
}

# ------------------------------ Lambda role --------------------------------

resource "aws_iam_role" "probe" {
  name = "${var.name_prefix}-probe-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "probe_logs" {
  role       = aws_iam_role.probe.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# The same guardrails as the operator role: explicit denies win over the allows below.
resource "aws_iam_role_policy_attachment" "probe_region_lock" {
  role       = aws_iam_role.probe.name
  policy_arn = aws_iam_policy.region_lock.arn
}

resource "aws_iam_role_policy_attachment" "probe_no_replication" {
  role       = aws_iam_role.probe.name
  policy_arn = aws_iam_policy.no_replication.arn
}

# Deliberately generous allows for the things the demo tries, so the explicit denies are what
# decide the outcome, plus read-only access for the status panels.
resource "aws_iam_role_policy" "probe_allow" {
  name = "probe-allow"
  role = aws_iam_role.probe.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ThingsTheDemoTries"
        Effect   = "Allow"
        Action   = ["ec2:CreateVpc", "kms:ListKeys", "kms:CreateKey", "lambda:ListFunctions", "rds:DescribeDBInstances"]
        Resource = "*"
      },
      {
        Sid      = "ProbeBuckets"
        Effect   = "Allow"
        Action   = ["s3:CreateBucket", "s3:DeleteBucket"]
        Resource = "arn:aws:s3:::${var.name_prefix}-probe-${local.account_id}-*"
      },
      {
        Sid      = "UploadTestObjects"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.payments.arn}/tests/*"
      },
      {
        Sid      = "TryReplication"
        Effect   = "Allow"
        Action   = "s3:PutReplicationConfiguration"
        Resource = aws_s3_bucket.payments.arn
      },
      {
        Sid      = "UseOurKey"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Encrypt", "kms:DescribeKey", "kms:GetKeyRotationStatus"]
        Resource = aws_kms_key.payments.arn
      },
      {
        Sid    = "ReadOnlyForStatusPanels"
        Effect = "Allow"
        Action = [
          "s3:GetEncryptionConfiguration", "s3:GetBucketPublicAccessBlock", "s3:GetBucketPolicy"
        ]
        Resource = aws_s3_bucket.payments.arn
      },
      {
        Sid      = "ReadSubscriptions"
        Effect   = "Allow"
        Action   = "sns:ListSubscriptionsByTopic"
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid      = "ReadComplianceAndMetrics"
        Effect   = "Allow"
        Action   = ["config:DescribeComplianceByConfigRule", "cloudwatch:GetMetricStatistics"]
        Resource = "*"
      }
    ]
  })
}

# ---------------------------- Lambda and API -------------------------------

data "archive_file" "probe" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.module}/probe-lambda.zip"
}

resource "aws_lambda_function" "probe" {
  function_name    = "${var.name_prefix}-probe-api"
  role             = aws_iam_role.probe.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.probe.output_path
  source_code_hash = data.archive_file.probe.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    # API_TOKEN is only set when var.api_token is non-empty, so the default demo stays open.
    variables = merge({
      APPROVED_REGION = var.approved_region
      BUCKET          = aws_s3_bucket.payments.bucket
      KEY_ARN         = aws_kms_key.payments.arn
      PREFIX          = var.name_prefix
      TOPIC_ARN       = aws_sns_topic.alerts.arn
      ACCOUNT_ID      = local.account_id
    }, var.api_token == "" ? {} : { API_TOKEN = var.api_token })
  }
}

resource "aws_apigatewayv2_api" "probe" {
  name          = "${var.name_prefix}-probe-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "probe" {
  api_id                 = aws_apigatewayv2_api.probe.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.probe.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "probe" {
  api_id    = aws_apigatewayv2_api.probe.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.probe.id}"
}

resource "aws_apigatewayv2_stage" "probe" {
  api_id      = aws_apigatewayv2_api.probe.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit  = 5
    throttling_burst_limit = 10
  }
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.probe.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.probe.execution_arn}/*/*"
}

# ----------------------------- Static site ---------------------------------

resource "aws_s3_bucket" "site" {
  bucket        = "${var.name_prefix}-site-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "index" {
  bucket       = aws_s3_bucket.site.id
  key          = "index.html"
  source       = "${path.module}/site/index.html"
  etag         = filemd5("${path.module}/site/index.html")
  content_type = "text/html; charset=utf-8"
}

resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "${var.name_prefix}-site-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  comment             = "${var.name_prefix} guardrail console"
  default_root_object = "index.html"
  price_class         = "PriceClass_100"

  origin {
    origin_id                = "site"
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.site.id
  }

  origin {
    origin_id   = "api"
    domain_name = replace(aws_apigatewayv2_api.probe.api_endpoint, "https://", "")

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "site"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.disabled.id
  }

  ordered_cache_behavior {
    path_pattern             = "/api/*"
    target_origin_id         = "api"
    viewer_protocol_policy   = "https-only"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "aws_s3_bucket_policy" "site" {
  bucket     = aws_s3_bucket.site.id
  depends_on = [aws_s3_bucket_public_access_block.site]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudFrontRead"
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.site.arn}/*"
      Condition = {
        StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.site.arn }
      }
    }]
  })
}

# Keep the demo bucket tidy: public test uploads expire after a day.
resource "aws_s3_bucket_lifecycle_configuration" "payments_tests" {
  bucket     = aws_s3_bucket.payments.id
  depends_on = [aws_s3_bucket_versioning.payments]

  rule {
    id     = "expire-demo-test-objects"
    status = "Enabled"

    filter {
      prefix = "tests/"
    }

    expiration {
      days = 1
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }
}

output "site_url" {
  description = "Your public live link (allow 5 to 15 minutes after apply for CloudFront)."
  value       = "https://${aws_cloudfront_distribution.site.domain_name}"
}
