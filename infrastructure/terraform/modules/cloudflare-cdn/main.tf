terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

# --- DNS Records ---

resource "cloudflare_record" "primary" {
  zone_id = var.cloudflare_zone_id
  name    = var.domain
  content = local.backend_host
  type    = "CNAME"
  proxied = true
  ttl     = 1 # Auto when proxied
}

resource "cloudflare_record" "alternatives" {
  for_each = toset(var.alternative_domains)

  zone_id = var.cloudflare_zone_id
  name    = each.value
  content = var.domain
  type    = "CNAME"
  proxied = true
  ttl     = 1
}

# --- Worker Script for Traffic Filtering ---

resource "cloudflare_worker_script" "filter" {
  account_id = data.cloudflare_zone.zone.account_id
  name       = "specter-filter-${var.redirector_id}"
  content    = templatefile("${path.module}/worker.js.tpl", {
    backend_url    = var.backend_url
    uri_pattern    = var.uri_pattern
    header_name    = var.header_name
    header_pattern = var.header_pattern
    decoy_response = var.decoy_response
    profile_id     = var.profile_id
  })
}

resource "cloudflare_worker_route" "filter_route" {
  zone_id     = var.cloudflare_zone_id
  pattern     = "${var.domain}/*"
  script_name = cloudflare_worker_script.filter.name
}

# --- Data Sources ---

data "cloudflare_zone" "zone" {
  zone_id = var.cloudflare_zone_id
}

locals {
  backend_host = regex("https?://([^:/]+)", var.backend_url)[0]
}
