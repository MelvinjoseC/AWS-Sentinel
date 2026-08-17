variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS Region to deploy resources to"
}

variable "schedule_expression" {
  type        = string
  default     = "rate(1 day)"
  description = "EventBridge cron expression for running Sentinel audits"
}

variable "slack_webhook_url" {
  type        = string
  default     = ""
  description = "Slack webhook URL for security compliance alerts"
  sensitive   = true
}

variable "teams_webhook_url" {
  type        = string
  default     = ""
  description = "MS Teams webhook URL for security compliance alerts"
  sensitive   = true
}

variable "assume_role_arn" {
  type        = string
  default     = ""
  description = "IAM Role ARN to assume for scanning target AWS account (optional)"
}

variable "assume_role_session_name" {
  type        = string
  default     = "AWSSentinelAuditorSession"
  description = "Session name when assuming the target IAM role"
}
