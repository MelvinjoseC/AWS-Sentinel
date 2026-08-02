output "lambda_arn" {
  value       = aws_lambda_function.sentinel_lambda.arn
  description = "The ARN of the deployed Sentinel Lambda function"
}

output "event_rule_arn" {
  value       = aws_cloudwatch_event_rule.daily_trigger.arn
  description = "The ARN of the EventBridge scheduling rule"
}
