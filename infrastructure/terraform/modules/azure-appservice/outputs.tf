output "redirector_id" {
  description = "Redirector identifier"
  value       = var.redirector_id
}

output "domain" {
  description = "Primary domain for the redirector"
  value       = var.domain
}

output "app_name" {
  description = "Azure Web App name"
  value       = azurerm_linux_web_app.redirector.name
}

output "app_default_hostname" {
  description = "Default hostname of the Web App"
  value       = azurerm_linux_web_app.redirector.default_hostname
}

output "app_url" {
  description = "Default URL of the Web App"
  value       = "https://${azurerm_linux_web_app.redirector.default_hostname}"
}

output "resource_group_name" {
  description = "Resource group name"
  value       = local.resource_group_name
}
