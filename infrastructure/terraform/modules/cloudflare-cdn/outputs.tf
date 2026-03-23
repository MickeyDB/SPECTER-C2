output "redirector_id" {
  description = "Redirector identifier"
  value       = var.redirector_id
}

output "domain" {
  description = "Primary domain for the redirector"
  value       = var.domain
}

output "worker_name" {
  description = "CloudFlare Worker script name"
  value       = cloudflare_worker_script.filter.name
}

output "dns_record_id" {
  description = "CloudFlare DNS record ID for the primary domain"
  value       = cloudflare_record.primary.id
}
