output "redirector_id" {
  description = "Redirector identifier"
  value       = var.redirector_id
}

output "domain" {
  description = "Primary domain for the redirector"
  value       = var.domain
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.cdn.id
}

output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name (for DNS CNAME)"
  value       = aws_cloudfront_distribution.cdn.domain_name
}

output "acm_certificate_arn" {
  description = "ACM certificate ARN"
  value       = aws_acm_certificate.cert.arn
}

output "lambda_edge_arn" {
  description = "Lambda@Edge function qualified ARN"
  value       = aws_lambda_function.edge.qualified_arn
}
