output "redirector_id" {
  description = "Redirector identifier"
  value       = var.redirector_id
}

output "domain" {
  description = "Primary domain for the redirector"
  value       = var.domain
}

output "public_ip" {
  description = "Public IP address of the VPS"
  value = (
    var.provider_type == "digitalocean"
    ? (length(digitalocean_droplet.redirector) > 0 ? digitalocean_droplet.redirector[0].ipv4_address : "")
    : (length(aws_instance.redirector) > 0 ? aws_instance.redirector[0].public_ip : "")
  )
}

output "instance_id" {
  description = "Cloud provider instance ID"
  value = (
    var.provider_type == "digitalocean"
    ? (length(digitalocean_droplet.redirector) > 0 ? tostring(digitalocean_droplet.redirector[0].id) : "")
    : (length(aws_instance.redirector) > 0 ? aws_instance.redirector[0].id : "")
  )
}
