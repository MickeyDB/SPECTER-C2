variable "redirector_id" {
  description = "Unique redirector identifier"
  type        = string
}

variable "domain" {
  description = "Primary domain for the CDN redirector"
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
}

variable "cloudflare_zone_id" {
  description = "CloudFlare zone ID for the domain"
  type        = string
}

variable "cloudflare_api_token" {
  description = "CloudFlare API token with DNS and Workers permissions"
  type        = string
  sensitive   = true
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
