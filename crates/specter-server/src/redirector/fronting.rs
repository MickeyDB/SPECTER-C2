use serde::{Deserialize, Serialize};

use super::{RedirectorConfig, RedirectorError, RedirectorProvider, RedirectorType};

// ── Domain fronting configuration ──────────────────────────────────────────

/// Configuration for CDN domain fronting.
///
/// Domain fronting exploits the difference between TLS SNI and HTTP Host
/// headers when both domains share the same CDN edge. The TLS connection
/// shows `front_domain` (a high-reputation domain) in the SNI field, while
/// the HTTP `Host` header carries `actual_domain` which routes to the
/// teamserver origin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainFrontingConfig {
    /// High-reputation domain visible in TLS SNI (e.g., "cdn.microsoft.com").
    /// This is the domain censors and network monitors see in the ClientHello.
    pub front_domain: String,

    /// Actual C2 domain in the HTTP Host header, routed by the CDN to the
    /// teamserver origin. Must be configured on the same CDN provider.
    pub actual_domain: String,
}

/// Validated domain fronting setup with provider-specific details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontingSetup {
    /// The fronting configuration.
    pub config: DomainFrontingConfig,

    /// Provider hosting both domains.
    pub provider: RedirectorProvider,

    /// SNI value the implant should use in TLS ClientHello.
    pub sni_domain: String,

    /// HTTP Host header value the implant should send.
    pub host_domain: String,

    /// The connect address the implant uses (CDN edge endpoint).
    pub connect_endpoint: String,
}

/// Validate a `RedirectorConfig` for domain fronting and produce a
/// `FrontingSetup` that can be pushed to implants.
pub fn validate_fronting_config(
    config: &RedirectorConfig,
) -> Result<FrontingSetup, RedirectorError> {
    if config.redirector_type != RedirectorType::DomainFront {
        return Err(RedirectorError::InvalidConfig(
            "redirector type must be DomainFront for fronting".to_string(),
        ));
    }

    let fronting = config.fronting.as_ref().ok_or_else(|| {
        RedirectorError::InvalidConfig(
            "domain fronting config is required when type is DomainFront".to_string(),
        )
    })?;

    if fronting.front_domain.is_empty() {
        return Err(RedirectorError::InvalidConfig(
            "front_domain must not be empty".to_string(),
        ));
    }

    if fronting.actual_domain.is_empty() {
        return Err(RedirectorError::InvalidConfig(
            "actual_domain must not be empty".to_string(),
        ));
    }

    if fronting.front_domain == fronting.actual_domain {
        return Err(RedirectorError::InvalidConfig(
            "front_domain and actual_domain must differ for fronting to be useful".to_string(),
        ));
    }

    let (connect_endpoint, sni_domain) = match config.provider {
        RedirectorProvider::CloudFlare => {
            // CloudFlare: both domains must be on CloudFlare. The implant
            // connects to the front_domain (which is proxied by CF). The
            // Host header carries the actual_domain so CF routes to its origin.
            (fronting.front_domain.clone(), fronting.front_domain.clone())
        }
        RedirectorProvider::AWS => {
            // AWS CloudFront: implant connects to the CloudFront edge
            // (*.cloudfront.net or front_domain CNAME). SNI = front_domain,
            // Host = actual_domain which is an alternate domain on the
            // distribution pointing to the teamserver origin.
            (fronting.front_domain.clone(), fronting.front_domain.clone())
        }
        ref p => {
            return Err(RedirectorError::InvalidConfig(format!(
                "domain fronting is not supported for provider: {p}"
            )));
        }
    };

    Ok(FrontingSetup {
        config: fronting.clone(),
        provider: config.provider.clone(),
        sni_domain,
        host_domain: fronting.actual_domain.clone(),
        connect_endpoint,
    })
}

/// Build the implant comms configuration update for domain fronting.
///
/// Returns a serializable structure that the teamserver can push to implants
/// via config update so they know which SNI and Host values to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplantFrontingUpdate {
    /// Domain to put in TLS SNI / ClientHello.
    pub sni_domain: String,

    /// Domain to put in HTTP Host header.
    pub host_domain: String,

    /// Endpoint to connect to (IP or hostname for TCP connection).
    pub connect_endpoint: String,

    /// Port to connect on (typically 443).
    pub port: u16,
}

/// Create an implant config update from a validated fronting setup.
pub fn build_implant_fronting_update(setup: &FrontingSetup, port: u16) -> ImplantFrontingUpdate {
    ImplantFrontingUpdate {
        sni_domain: setup.sni_domain.clone(),
        host_domain: setup.host_domain.clone(),
        connect_endpoint: setup.connect_endpoint.clone(),
        port,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redirector::{FilteringRules, TlsCertMode};

    fn make_fronting_config(
        provider: RedirectorProvider,
        fronting: Option<DomainFrontingConfig>,
    ) -> RedirectorConfig {
        RedirectorConfig {
            id: "front-001".to_string(),
            name: "cf-fronted".to_string(),
            redirector_type: RedirectorType::DomainFront,
            provider,
            domain: "actual.example.com".to_string(),
            alternative_domains: vec![],
            tls_cert_mode: TlsCertMode::ProviderManaged,
            backend_url: "https://teamserver.internal:443".to_string(),
            filtering_rules: FilteringRules {
                profile_id: "profile-abc".to_string(),
                decoy_response: "<html>404</html>".to_string(),
            },
            health_check_interval: 60,
            auto_rotate_on_block: true,
            azure_location: "westeurope".to_string(),
            fronting,
        }
    }

    #[test]
    fn test_validate_cloudflare_fronting() {
        let config = make_fronting_config(
            RedirectorProvider::CloudFlare,
            Some(DomainFrontingConfig {
                front_domain: "cdn.legitimate-site.com".to_string(),
                actual_domain: "c2.example.com".to_string(),
            }),
        );

        let setup = validate_fronting_config(&config).unwrap();
        assert_eq!(setup.sni_domain, "cdn.legitimate-site.com");
        assert_eq!(setup.host_domain, "c2.example.com");
        assert_eq!(setup.connect_endpoint, "cdn.legitimate-site.com");
        assert_eq!(setup.provider, RedirectorProvider::CloudFlare);
    }

    #[test]
    fn test_validate_aws_fronting() {
        let config = make_fronting_config(
            RedirectorProvider::AWS,
            Some(DomainFrontingConfig {
                front_domain: "d1234567.cloudfront.net".to_string(),
                actual_domain: "c2.example.com".to_string(),
            }),
        );

        let setup = validate_fronting_config(&config).unwrap();
        assert_eq!(setup.sni_domain, "d1234567.cloudfront.net");
        assert_eq!(setup.host_domain, "c2.example.com");
        assert_eq!(setup.connect_endpoint, "d1234567.cloudfront.net");
        assert_eq!(setup.provider, RedirectorProvider::AWS);
    }

    #[test]
    fn test_validate_missing_fronting_config() {
        let config = make_fronting_config(RedirectorProvider::CloudFlare, None);
        let err = validate_fronting_config(&config).unwrap_err();
        assert!(err
            .to_string()
            .contains("domain fronting config is required"));
    }

    #[test]
    fn test_validate_empty_front_domain() {
        let config = make_fronting_config(
            RedirectorProvider::CloudFlare,
            Some(DomainFrontingConfig {
                front_domain: "".to_string(),
                actual_domain: "c2.example.com".to_string(),
            }),
        );
        let err = validate_fronting_config(&config).unwrap_err();
        assert!(err.to_string().contains("front_domain must not be empty"));
    }

    #[test]
    fn test_validate_empty_actual_domain() {
        let config = make_fronting_config(
            RedirectorProvider::AWS,
            Some(DomainFrontingConfig {
                front_domain: "front.example.com".to_string(),
                actual_domain: "".to_string(),
            }),
        );
        let err = validate_fronting_config(&config).unwrap_err();
        assert!(err.to_string().contains("actual_domain must not be empty"));
    }

    #[test]
    fn test_validate_same_domains() {
        let config = make_fronting_config(
            RedirectorProvider::CloudFlare,
            Some(DomainFrontingConfig {
                front_domain: "same.example.com".to_string(),
                actual_domain: "same.example.com".to_string(),
            }),
        );
        let err = validate_fronting_config(&config).unwrap_err();
        assert!(err.to_string().contains("must differ"));
    }

    #[test]
    fn test_validate_wrong_type() {
        let mut config = make_fronting_config(
            RedirectorProvider::CloudFlare,
            Some(DomainFrontingConfig {
                front_domain: "front.example.com".to_string(),
                actual_domain: "actual.example.com".to_string(),
            }),
        );
        config.redirector_type = RedirectorType::CDN;
        let err = validate_fronting_config(&config).unwrap_err();
        assert!(err.to_string().contains("type must be DomainFront"));
    }

    #[test]
    fn test_validate_unsupported_provider() {
        let config = make_fronting_config(
            RedirectorProvider::DigitalOcean,
            Some(DomainFrontingConfig {
                front_domain: "front.example.com".to_string(),
                actual_domain: "actual.example.com".to_string(),
            }),
        );
        let err = validate_fronting_config(&config).unwrap_err();
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn test_build_implant_fronting_update() {
        let setup = FrontingSetup {
            config: DomainFrontingConfig {
                front_domain: "cdn.legitimate.com".to_string(),
                actual_domain: "c2.hidden.com".to_string(),
            },
            provider: RedirectorProvider::CloudFlare,
            sni_domain: "cdn.legitimate.com".to_string(),
            host_domain: "c2.hidden.com".to_string(),
            connect_endpoint: "cdn.legitimate.com".to_string(),
        };

        let update = build_implant_fronting_update(&setup, 443);
        assert_eq!(update.sni_domain, "cdn.legitimate.com");
        assert_eq!(update.host_domain, "c2.hidden.com");
        assert_eq!(update.connect_endpoint, "cdn.legitimate.com");
        assert_eq!(update.port, 443);
    }

    #[test]
    fn test_fronting_config_serde_roundtrip() {
        let fc = DomainFrontingConfig {
            front_domain: "cdn.legit.com".to_string(),
            actual_domain: "c2.real.com".to_string(),
        };

        let json = serde_json::to_string(&fc).unwrap();
        let parsed: DomainFrontingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, fc);

        let yaml = serde_yaml::to_string(&fc).unwrap();
        let parsed_yaml: DomainFrontingConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed_yaml, fc);
    }

    #[test]
    fn test_implant_update_serde_roundtrip() {
        let update = ImplantFrontingUpdate {
            sni_domain: "cdn.legit.com".to_string(),
            host_domain: "c2.real.com".to_string(),
            connect_endpoint: "cdn.legit.com".to_string(),
            port: 443,
        };

        let json = serde_json::to_string(&update).unwrap();
        let parsed: ImplantFrontingUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sni_domain, update.sni_domain);
        assert_eq!(parsed.host_domain, update.host_domain);
        assert_eq!(parsed.port, update.port);
    }
}
