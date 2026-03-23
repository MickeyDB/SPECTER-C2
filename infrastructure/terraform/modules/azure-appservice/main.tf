terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

locals {
  rg_name  = var.resource_group_name != "" ? var.resource_group_name : "specter-ws-${var.redirector_id}"
  create_rg = var.resource_group_name == ""
  app_name = "specter-ws-${var.redirector_id}"
}

# --- Resource Group ---

resource "azurerm_resource_group" "redir" {
  count    = local.create_rg ? 1 : 0
  name     = local.rg_name
  location = var.azure_location

  tags = {
    RedirectorID = var.redirector_id
    Purpose      = "specter-c2-redirector"
  }
}

data "azurerm_resource_group" "existing" {
  count = local.create_rg ? 0 : 1
  name  = local.rg_name
}

locals {
  resource_group_name     = local.create_rg ? azurerm_resource_group.redir[0].name : data.azurerm_resource_group.existing[0].name
  resource_group_location = local.create_rg ? azurerm_resource_group.redir[0].location : data.azurerm_resource_group.existing[0].location
}

# --- App Service Plan ---

resource "azurerm_service_plan" "redir" {
  name                = "${local.app_name}-plan"
  resource_group_name = local.resource_group_name
  location            = local.resource_group_location
  os_type             = "Linux"
  sku_name            = var.sku_name

  tags = {
    RedirectorID = var.redirector_id
  }
}

# --- Linux Web App ---

resource "azurerm_linux_web_app" "redirector" {
  name                = local.app_name
  resource_group_name = local.resource_group_name
  location            = azurerm_service_plan.redir.location
  service_plan_id     = azurerm_service_plan.redir.id

  site_config {
    always_on          = true
    websockets_enabled = true
    minimum_tls_version = "1.2"

    application_stack {
      node_version = "20-lts"
    }

    app_command_line = "node server.js"

    # Suppress Azure default headers
    remote_debugging_enabled = false
  }

  app_settings = {
    "BACKEND_URL"                      = var.backend_url
    "URI_PATTERN"                      = var.uri_pattern
    "HEADER_NAME"                      = var.header_name
    "HEADER_PATTERN"                   = var.header_pattern
    "DECOY_RESPONSE"                   = var.decoy_response
    "PROFILE_ID"                       = var.profile_id
    "WEBSITE_RUN_FROM_PACKAGE"         = "0"
    "SCM_DO_BUILD_DURING_DEPLOYMENT"   = "true"
    "WEBSITE_NODE_DEFAULT_VERSION"     = "~20"
  }

  https_only = true

  # Disable detailed error pages and Azure branding
  logs {
    http_logs {
      file_system {
        retention_in_days = 1
        retention_in_mb   = 25
      }
    }
  }

  tags = {
    RedirectorID = var.redirector_id
  }
}

# --- Custom Domain + Managed TLS ---

resource "azurerm_dns_cname_record" "app" {
  count               = var.dns_zone_name != "" ? 1 : 0
  name                = split(".", var.domain)[0]
  zone_name           = var.dns_zone_name
  resource_group_name = var.dns_zone_resource_group != "" ? var.dns_zone_resource_group : local.resource_group_name
  ttl                 = 300
  record              = azurerm_linux_web_app.redirector.default_hostname
}

resource "azurerm_dns_txt_record" "app_verify" {
  count               = var.dns_zone_name != "" ? 1 : 0
  name                = "asuid.${split(".", var.domain)[0]}"
  zone_name           = var.dns_zone_name
  resource_group_name = var.dns_zone_resource_group != "" ? var.dns_zone_resource_group : local.resource_group_name
  ttl                 = 300

  record {
    value = azurerm_linux_web_app.redirector.custom_domain_verification_id
  }
}

resource "azurerm_app_service_custom_hostname_binding" "app" {
  count               = var.dns_zone_name != "" ? 1 : 0
  hostname            = var.domain
  app_service_name    = azurerm_linux_web_app.redirector.name
  resource_group_name = local.resource_group_name

  depends_on = [
    azurerm_dns_cname_record.app,
    azurerm_dns_txt_record.app_verify,
  ]
}

resource "azurerm_app_service_managed_certificate" "app" {
  count                      = var.dns_zone_name != "" ? 1 : 0
  custom_hostname_binding_id = azurerm_app_service_custom_hostname_binding.app[0].id
}

resource "azurerm_app_service_certificate_binding" "app" {
  count               = var.dns_zone_name != "" ? 1 : 0
  hostname_binding_id = azurerm_app_service_custom_hostname_binding.app[0].id
  certificate_id      = azurerm_app_service_managed_certificate.app[0].id
  ssl_state           = "SniEnabled"
}

# --- Deploy Application Code ---

resource "null_resource" "deploy_app" {
  depends_on = [azurerm_linux_web_app.redirector]

  triggers = {
    backend_url = var.backend_url
    app_hash    = filesha256("${path.module}/app/server.js")
  }

  provisioner "local-exec" {
    working_dir = "${path.module}/app"
    command     = <<-EOT
      zip -r ../deploy.zip . -x "node_modules/*"

      az webapp deploy \
        --resource-group ${local.resource_group_name} \
        --name ${azurerm_linux_web_app.redirector.name} \
        --src-path ../deploy.zip \
        --type zip

      rm -f ../deploy.zip
    EOT
  }
}
