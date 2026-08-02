provider "aws" {
  region = var.aws_region
}

# Zip the python script and configuration files for deployment
data "archive_file" "sentinel_zip" {
  type        = "zip"
  source_dir  = "${path.module}/.."
  output_path = "${path.module}/sentinel.zip"
  excludes    = [".git", "terraform", "tests", ".github", "venv", ".pytest_cache", "__pycache__", "Dockerfile", "docker-compose.yml"]
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "aws-sentinel-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Policy for Lambda permissions (Auditing & Remediation)
resource "aws_iam_policy" "lambda_policy" {
  name        = "aws-sentinel-lambda-policy"
  description = "Permissions required by AWS Sentinel Auditor to inspect S3, IAM, and EC2 Security Groups"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # S3 permissions
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetPublicAccessBlock",
          "s3:PutPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:PutEncryptionConfiguration",
          "s3:GetBucketVersioning",
          "s3:PutBucketVersioning",
          
          # IAM permissions
          "iam:ListUsers",
          "iam:ListMFADevices",
          "iam:ListAccessKeys",
          "iam:GetAccountPasswordPolicy",
          
          # EC2 permissions
          "ec2:DescribeRegions",
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress",
          
          # CloudWatch Logs permissions
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# Lambda Function
resource "aws_lambda_function" "sentinel_lambda" {
  filename         = data.archive_file.sentinel_zip.output_path
  source_code_hash = data.archive_file.sentinel_zip.output_base64sha256
  function_name    = "aws-sentinel-auditor"
  role             = aws_iam_role.lambda_role.arn
  handler          = "sentinel.lambda_handler"
  runtime          = "python3.10"
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      SLACK_WEBHOOK = var.slack_webhook_url
      TEAMS_WEBHOOK = var.teams_webhook_url
    }
  }
}

# EventBridge Trigger Configuration
resource "aws_cloudwatch_event_rule" "daily_trigger" {
  name                = "aws-sentinel-daily-schedule"
  description         = "Trigger compliance audit daily"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.daily_trigger.name
  target_id = "run-sentinel-lambda"
  arn       = aws_lambda_function.sentinel_lambda.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sentinel_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_trigger.arn
}
