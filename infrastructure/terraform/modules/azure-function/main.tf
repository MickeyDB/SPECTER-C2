terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

locals {
  rg_name      = var.resource_group_name != "" ? var.resource_group_name : "specter-redir-${var.redirector_id}"
  create_rg    = var.resource_group_name == ""
  func_name    = "specter-fn-${var.redirector_id}"
  storage_name = replace("specterredir${substr(var.redirector_id, 0, 10)}", "-", "")
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

# --- Storage Account for Function App ---

resource "azurerm_storage_account" "func" {
  name                     = local.storage_name
  resource_group_name      = local.resource_group_name
  location                 = local.resource_group_location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    RedirectorID = var.redirector_id
  }
}

# --- App Service Plan (Consumption) ---

resource "azurerm_service_plan" "func" {
  name                = "specter-plan-${var.redirector_id}"
  resource_group_name = local.resource_group_name
  location            = local.resource_group_location
  os_type             = "Linux"
  sku_name            = "Y1" # Consumption plan

  tags = {
    RedirectorID = var.redirector_id
  }
}

# --- Function App ---

resource "azurerm_linux_function_app" "redirector" {
  name                       = local.func_name
  resource_group_name        = local.resource_group_name
  location                   = local.resource_group_location
  service_plan_id            = azurerm_service_plan.func.id
  storage_account_name       = azurerm_storage_account.func.name
  storage_account_access_key = azurerm_storage_account.func.primary_access_key

  site_config {
    application_stack {
      node_version = "20"
    }

    # Minimum TLS version
    minimum_tls_version = "1.2"
  }

  app_settings = {
    "BACKEND_URL"          = var.backend_url
    "URI_PATTERN"          = var.uri_pattern
    "HEADER_NAME"          = var.header_name
    "HEADER_PATTERN"       = var.header_pattern
    "DECOY_RESPONSE"       = var.decoy_response
    "PROFILE_ID"           = var.profile_id
    "FUNCTIONS_WORKER_RUNTIME" = "node"
  }

  https_only = true

  tags = {
    RedirectorID = var.redirector_id
  }
}

# --- Custom Domain + Managed TLS ---

resource "azurerm_dns_cname_record" "func" {
  count               = var.dns_zone_name != "" ? 1 : 0
  name                = split(".", var.domain)[0]
  zone_name           = var.dns_zone_name
  resource_group_name = var.dns_zone_resource_group != "" ? var.dns_zone_resource_group : local.resource_group_name
  ttl                 = 300
  record              = azurerm_linux_function_app.redirector.default_hostname
}

resource "azurerm_dns_txt_record" "func_verify" {
  count               = var.dns_zone_name != "" ? 1 : 0
  name                = "asuid.${split(".", var.domain)[0]}"
  zone_name           = var.dns_zone_name
  resource_group_name = var.dns_zone_resource_group != "" ? var.dns_zone_resource_group : local.resource_group_name
  ttl                 = 300

  record {
    value = azurerm_linux_function_app.redirector.custom_domain_verification_id
  }
}

resource "azurerm_app_service_custom_hostname_binding" "func" {
  count               = var.dns_zone_name != "" ? 1 : 0
  hostname            = var.domain
  app_service_name    = azurerm_linux_function_app.redirector.name
  resource_group_name = local.resource_group_name

  depends_on = [
    azurerm_dns_cname_record.func,
    azurerm_dns_txt_record.func_verify,
  ]
}

resource "azurerm_app_service_managed_certificate" "func" {
  count                      = var.dns_zone_name != "" ? 1 : 0
  custom_hostname_binding_id = azurerm_app_service_custom_hostname_binding.func[0].id
}

resource "azurerm_app_service_certificate_binding" "func" {
  count               = var.dns_zone_name != "" ? 1 : 0
  hostname_binding_id = azurerm_app_service_custom_hostname_binding.func[0].id
  certificate_id      = azurerm_app_service_managed_certificate.func[0].id
  ssl_state           = "SniEnabled"
}
