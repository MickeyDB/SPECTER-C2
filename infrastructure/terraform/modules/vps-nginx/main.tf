terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  all_domains  = concat([var.domain], var.alternative_domains)
  server_names = join(" ", local.all_domains)

  cloud_init = templatefile("${path.module}/cloud-init.yaml.tpl", {
    domain         = var.domain
    server_names   = local.server_names
    backend_url    = var.backend_url
    uri_pattern    = var.uri_pattern
    header_name    = var.header_name
    header_pattern = var.header_pattern
    decoy_response = var.decoy_response
    certbot_email  = var.certbot_email
    certbot_domains = join(" -d ", local.all_domains)
  })
}

# --- DigitalOcean Droplet ---

resource "digitalocean_ssh_key" "deployer" {
  count      = var.provider_type == "digitalocean" ? 1 : 0
  name       = "specter-${var.redirector_id}"
  public_key = var.ssh_public_key
}

resource "digitalocean_droplet" "redirector" {
  count    = var.provider_type == "digitalocean" ? 1 : 0
  image    = "ubuntu-22-04-x64"
  name     = "specter-redir-${var.redirector_id}"
  region   = var.do_region
  size     = var.do_size
  ssh_keys = [digitalocean_ssh_key.deployer[0].fingerprint]

  user_data = local.cloud_init

  tags = ["specter", "redirector", var.redirector_id]
}

resource "digitalocean_firewall" "redirector" {
  count = var.provider_type == "digitalocean" ? 1 : 0
  name  = "specter-redir-${var.redirector_id}"

  droplet_ids = [digitalocean_droplet.redirector[0].id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# --- AWS EC2 Instance ---

resource "aws_key_pair" "deployer" {
  count      = var.provider_type == "aws" ? 1 : 0
  key_name   = "specter-${var.redirector_id}"
  public_key = var.ssh_public_key
}

resource "aws_security_group" "redirector" {
  count       = var.provider_type == "aws" ? 1 : 0
  name        = "specter-redir-${var.redirector_id}"
  description = "SPECTER redirector ${var.redirector_id}"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name         = "specter-redir-${var.redirector_id}"
    RedirectorID = var.redirector_id
  }
}

resource "aws_instance" "redirector" {
  count                  = var.provider_type == "aws" ? 1 : 0
  ami                    = var.aws_ami_id
  instance_type          = var.aws_instance_type
  key_name               = aws_key_pair.deployer[0].key_name
  vpc_security_group_ids = [aws_security_group.redirector[0].id]
  subnet_id              = var.aws_subnet_id != "" ? var.aws_subnet_id : null
  user_data              = local.cloud_init

  tags = {
    Name         = "specter-redir-${var.redirector_id}"
    RedirectorID = var.redirector_id
  }
}
