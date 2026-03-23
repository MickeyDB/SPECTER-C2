variable "redirector_id" {
  description = "Unique redirector identifier"
  type        = string
}

variable "domain" {
  description = "Custom domain for the Function App"
  type        = string
}

variable "backend_url" {
  description = "Teamserver backend origin URL"
  type        = string
}

variable "profile_id" {
  description = "C2 profile ID for traffic filtering"
  type        = string
}

variable "decoy_response" {
  description = "HTML body to serve for non-matching requests"
  type        = string
  default     = "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>"
}

variable "uri_pattern" {
  description = "URI regex pattern that identifies C2 traffic"
  type        = string
  default     = "^/api/v[0-9]+/"
}

variable "header_name" {
  description = "HTTP header name for C2 traffic identification"
  type        = string
  default     = "X-Request-ID"
}

variable "header_pattern" {
  description = "Regex pattern for the C2 identification header value"
  type        = string
  default     = "^[a-f0-9]{32}$"
}

variable "azure_location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Existing resource group name (if empty, a new one is created)"
  type        = string
  default     = ""
}

variable "dns_zone_name" {
  description = "Azure DNS zone name for custom domain validation"
  type        = string
  default     = ""
}

variable "dns_zone_resource_group" {
  description = "Resource group containing the Azure DNS zone"
  type        = string
  default     = ""
}
