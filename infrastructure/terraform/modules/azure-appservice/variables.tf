variable "redirector_id" {
  description = "Unique redirector identifier"
  type        = string
}

variable "domain" {
  description = "Custom domain for the App Service"
  type        = string
}

variable "alternative_domains" {
  description = "Additional domains to serve"
  type        = list(string)
  default     = []
}

variable "backend_url" {
  description = "Teamserver backend origin URL"
  type        = string

  validation {
    condition     = can(regex("^https?://", var.backend_url))
    error_message = "Backend URL must start with http:// or https://"
  }
}

variable "profile_id" {
  description = "C2 profile ID for traffic filtering"
  type        = string
}

variable "decoy_response" {
  description = "HTML body to serve for non-matching requests"
  type        = string
  default     = "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>"
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
  description = "Azure region for deployment"
  type        = string
  default     = "eastus"
}

variable "sku_name" {
  description = "App Service Plan SKU (B1 = Basic, B2, B3, P1v2 = Premium)"
  type        = string
  default     = "B1"

  validation {
    condition     = contains(["B1", "B2", "B3", "P1v2", "P2v2", "P3v2", "S1", "S2", "S3"], var.sku_name)
    error_message = "SKU must be one of: B1, B2, B3, P1v2, P2v2, P3v2, S1, S2, S3"
  }
}

variable "resource_group_name" {
  description = "Existing resource group name (if empty, a new one is created)"
  type        = string
  default     = ""
}

variable "dns_zone_name" {
  description = "Azure DNS zone name for custom domain validation (leave empty to skip custom domain)"
  type        = string
  default     = ""
}

variable "dns_zone_resource_group" {
  description = "Resource group containing the Azure DNS zone"
  type        = string
  default     = ""
}
