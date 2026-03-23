output "redirector_id" {
  description = "Redirector identifier"
  value       = var.redirector_id
}

output "domain" {
  description = "Primary domain for the redirector"
  value       = var.domain
}

output "function_app_name" {
  description = "Azure Function App name"
  value       = azurerm_linux_function_app.redirector.name
}

output "function_app_default_hostname" {
  description = "Default hostname of the Function App"
  value       = azurerm_linux_function_app.redirector.default_hostname
}

output "function_app_url" {
  description = "Default URL of the Function App"
  value       = "https://${azurerm_linux_function_app.redirector.default_hostname}"
}

output "resource_group_name" {
  description = "Resource group name"
  value       = local.resource_group_name
}
