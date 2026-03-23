variable "redirector_id" {
  description = "Unique redirector identifier"
  type        = string
}

variable "domain" {
  description = "Primary domain for the nginx reverse proxy"
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
  description = "URI regex pattern that identifies C2 traffic (nginx regex syntax)"
  type        = string
  default     = "^/api/v[0-9]+/"
}

variable "header_name" {
  description = "HTTP header name for C2 traffic identification"
  type        = string
  default     = "X-Request-ID"
}

variable "header_pattern" {
  description = "Regex pattern for the C2 identification header value (nginx regex syntax)"
  type        = string
  default     = "^[a-f0-9]{32}$"
}

variable "certbot_email" {
  description = "Email address for Let's Encrypt certificate registration"
  type        = string
}

# --- Provider-specific variables ---

variable "provider_type" {
  description = "Cloud provider: digitalocean or aws"
  type        = string
  default     = "digitalocean"

  validation {
    condition     = contains(["digitalocean", "aws"], var.provider_type)
    error_message = "provider_type must be 'digitalocean' or 'aws'"
  }
}

# DigitalOcean variables
variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  default     = ""
  sensitive   = true
}

variable "do_region" {
  description = "DigitalOcean region"
  type        = string
  default     = "nyc3"
}

variable "do_size" {
  description = "DigitalOcean droplet size"
  type        = string
  default     = "s-1vcpu-1gb"
}

# AWS variables
variable "aws_region" {
  description = "AWS region for the EC2 instance"
  type        = string
  default     = "us-east-1"
}

variable "aws_instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "aws_ami_id" {
  description = "AMI ID for the EC2 instance (Ubuntu 22.04)"
  type        = string
  default     = ""
}

variable "aws_subnet_id" {
  description = "Subnet ID for the EC2 instance"
  type        = string
  default     = ""
}

variable "ssh_public_key" {
  description = "SSH public key for instance access"
  type        = string
}
