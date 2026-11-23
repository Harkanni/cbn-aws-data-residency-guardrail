# ---------------------------------------------------------------------------
# presenter.tf - runs the FULL demo (migration, drift, admin-level tests) in AWS, behind a key.
# Needs main.tf, hosting.tf and migration.tf in the same folder.
#
#   Browser --/api/presenter/*--> CloudFront --> API Gateway --> presenter Lambda
#                                                         |--> Lambda job (async): DynamoDB copy / EC2 image copy
#                                                         |--> DynamoDB state table (progress the page polls)
#
# Public visitors still only get the safe probes. These controls need the demo key:
#     ./deploy.sh demo-key        (prints it; type it into "Presenter mode" on the page)
# The Lambda role carries the inbound-only policy from migration.tf: reads from the legacy region
# are allowed, every write must target the approved region. RunInstances is limited to t3.micro.
# Click "Reset migration" before `./deploy.sh destroy`: the migrated server and image are created
# at run time and Terraform does not know about them.
# ---------------------------------------------------------------------------

resource "random_password" "demo_key" {
  length  = 20
  special = false
}

resource "aws_dynamodb_table" "demo_state" {
  name         = "${var.name_prefix}-demo-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

# Lets the Lambda restore the bucket policy after the "delete the bucket policy" drift demo.
resource "aws_ssm_parameter" "bucket_policy" {
  name  = "/${var.name_prefix}/payments-bucket-policy"
  type  = "String"
  value = aws_s3_bucket_policy.payments.policy
}

locals {
  presenter_fn_name = "${var.name_prefix}-presenter-api"
}

resource "aws_iam_role" "presenter" {
  name = "${var.name_prefix}-presenter-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "presenter_logs" {
  role       = aws_iam_role.presenter.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "presenter_inbound_only" {
  role       = aws_iam_role.presenter.name
  policy_arn = aws_iam_policy.inbound_only.arn
}

resource "aws_iam_role_policy" "presenter_allow" {
  name = "presenter-allow"
  role = aws_iam_role.presenter.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Databases"
        Effect = "Allow"
        Action = ["dynamodb:Scan", "dynamodb:DescribeTable", "dynamodb:BatchWriteItem", "dynamodb:PutItem", "dynamodb:GetItem"]
        Resource = [
          aws_dynamodb_table.legacy.arn, aws_dynamodb_table.migrated.arn, aws_dynamodb_table.demo_state.arn,
          "arn:aws:dynamodb:us-east-1:${local.account_id}:table/${aws_dynamodb_table.migrated.name}"
        ]
      },
      {
        Sid    = "ImageAndServerMigration"
        Effect = "Allow"
        Action = [
          "ec2:CopyImage", "ec2:CopySnapshot", "ec2:CreateSnapshot", "ec2:CreateVolume", "ec2:CreateTags",
          "ec2:DeregisterImage", "ec2:DeleteSnapshot", "ec2:TerminateInstances", "ec2:Describe*"
        ]
        Resource = "*"
      },
      {
        Sid    = "RunInstancesOnlyT3Micro"
        Effect = "Allow"
        Action = "ec2:RunInstances"
        Resource = [
          "arn:aws:ec2:${var.approved_region}:${local.account_id}:instance/*"
        ]
        Condition = { StringEquals = { "ec2:InstanceType" = "t3.micro" } }
      },
      {
        Sid    = "RunInstancesSupportingResources"
        Effect = "Allow"
        Action = "ec2:RunInstances"
        Resource = [
          "arn:aws:ec2:${var.approved_region}::image/*",
          "arn:aws:ec2:${var.approved_region}:${local.account_id}:subnet/*",
          "arn:aws:ec2:${var.approved_region}:${local.account_id}:security-group/*",
          "arn:aws:ec2:${var.approved_region}:${local.account_id}:network-interface/*",
          "arn:aws:ec2:${var.approved_region}:${local.account_id}:volume/*"
        ]
      },
      {
        Sid    = "OurKey"
        Effect = "Allow"
        Action = [
          "kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*", "kms:DescribeKey", "kms:CreateGrant",
          "kms:DisableKeyRotation", "kms:EnableKeyRotation", "kms:GetKeyRotationStatus"
        ]
        Resource = aws_kms_key.payments.arn
      },
      {
        Sid    = "PaymentsBucketDriftAndFix"
        Effect = "Allow"
        Action = [
          "s3:PutEncryptionConfiguration", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy",
          "s3:PutBucketPublicAccessBlock", "s3:PutReplicationConfiguration"
        ]
        Resource = aws_s3_bucket.payments.arn
      },
      {
        Sid      = "ReadPolicyCopy"
        Effect   = "Allow"
        Action   = "ssm:GetParameter"
        Resource = aws_ssm_parameter.bucket_policy.arn
      },
      {
        Sid      = "StartOwnJobs"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = "arn:aws:lambda:${var.approved_region}:${local.account_id}:function:${local.presenter_fn_name}"
      }
    ]
  })
}

resource "aws_lambda_function" "presenter" {
  function_name    = local.presenter_fn_name
  role             = aws_iam_role.presenter.arn
  runtime          = "python3.12"
  handler          = "presenter.handler"
  filename         = data.archive_file.probe.output_path
  source_code_hash = data.archive_file.probe.output_base64sha256
  timeout          = 900
  memory_size      = 256

  environment {
    variables = {
      APPROVED_REGION = var.approved_region
      BUCKET          = aws_s3_bucket.payments.bucket
      KEY_ARN         = aws_kms_key.payments.arn
      PREFIX          = var.name_prefix
      ACCOUNT_ID      = local.account_id
      LEGACY_REGION   = var.legacy_region
      LEGACY_TABLE    = aws_dynamodb_table.legacy.name
      DEST_TABLE      = aws_dynamodb_table.migrated.name
      LEGACY_AMI      = aws_ami_from_instance.legacy.id
      DEMO_KEY        = random_password.demo_key.result
      STATE_TABLE     = aws_dynamodb_table.demo_state.name
      POLICY_PARAM    = aws_ssm_parameter.bucket_policy.name
    }
  }
}

resource "aws_apigatewayv2_integration" "presenter" {
  api_id                 = aws_apigatewayv2_api.probe.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.presenter.invoke_arn
  payload_format_version = "2.0"
}

# More specific than the $default route, so presenter calls go to the presenter Lambda.
resource "aws_apigatewayv2_route" "presenter" {
  api_id    = aws_apigatewayv2_api.probe.id
  route_key = "ANY /api/presenter/{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.presenter.id}"
}

resource "aws_lambda_permission" "apigw_presenter" {
  statement_id  = "AllowApiGatewayInvokePresenter"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.presenter.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.probe.execution_arn}/*/*"
}

output "demo_key" {
  description = "Type this into Presenter mode on the live page. Print with ./deploy.sh demo-key."
  value       = random_password.demo_key.result
  sensitive   = true
}
