terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  all_domains  = concat([var.domain], var.alternative_domains)
  backend_host = regex("https?://([^:/]+)", var.backend_url)[0]
}

# --- ACM Certificate (must be in us-east-1 for CloudFront) ---

resource "aws_acm_certificate" "cert" {
  domain_name               = var.domain
  subject_alternative_names = var.alternative_domains
  validation_method         = "DNS"

  tags = {
    Name        = "specter-${var.redirector_id}"
    RedirectorID = var.redirector_id
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate_validation" "cert" {
  certificate_arn = aws_acm_certificate.cert.arn

  # If Route53 zone is provided, use DNS validation records
  validation_record_fqdns = var.route53_zone_id != "" ? [
    for record in aws_route53_record.cert_validation : record.fqdn
  ] : null
}

resource "aws_route53_record" "cert_validation" {
  for_each = var.route53_zone_id != "" ? {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.route53_zone_id
}

# --- Lambda@Edge for Request Inspection ---

data "archive_file" "lambda_edge" {
  type        = "zip"
  output_path = "${path.module}/lambda_edge.zip"

  source {
    content  = templatefile("${path.module}/lambda_edge.js.tpl", {
      backend_url    = var.backend_url
      uri_pattern    = var.uri_pattern
      header_name    = var.header_name
      header_pattern = var.header_pattern
      decoy_response = var.decoy_response
      profile_id     = var.profile_id
    })
    filename = "index.js"
  }
}

resource "aws_iam_role" "lambda_edge" {
  name = "specter-edge-${var.redirector_id}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = [
          "lambda.amazonaws.com",
          "edgelambda.amazonaws.com",
        ]
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_edge.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "edge" {
  function_name    = "specter-filter-${var.redirector_id}"
  role             = aws_iam_role.lambda_edge.arn
  handler          = "index.handler"
  runtime          = "nodejs20.x"
  filename         = data.archive_file.lambda_edge.output_path
  source_code_hash = data.archive_file.lambda_edge.output_base64sha256
  publish          = true

  tags = {
    Name         = "specter-${var.redirector_id}"
    RedirectorID = var.redirector_id
  }
}

# --- CloudFront Distribution ---

resource "aws_cloudfront_distribution" "cdn" {
  enabled             = true
  comment             = "SPECTER redirector ${var.redirector_id}"
  aliases             = local.all_domains
  default_root_object = ""
  price_class         = "PriceClass_100"

  origin {
    domain_name = local.backend_host
    origin_id   = "teamserver"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "teamserver"

    forwarded_values {
      query_string = true
      headers      = ["Host", var.header_name, "User-Agent"]

      cookies {
        forward = "all"
      }
    }

    viewer_protocol_policy = "https-only"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
    compress               = true

    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = aws_lambda_function.edge.qualified_arn
      include_body = true
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.cert.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = {
    Name         = "specter-${var.redirector_id}"
    RedirectorID = var.redirector_id
  }
}
