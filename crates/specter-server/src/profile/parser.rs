use super::schema::*;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("YAML parse error: {0}")]
    YamlParse(#[from] serde_yaml::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Warning produced during profile validation (non-fatal).
#[derive(Debug, Clone)]
pub struct Warning {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

/// Parse a YAML string into a `Profile`.
pub fn parse_profile(yaml_str: &str) -> Result<Profile, ProfileError> {
    let profile: Profile = serde_yaml::from_str(yaml_str)?;
    Ok(profile)
}

/// Validate a parsed profile and return any warnings.
///
/// Returns `Err` for fatal issues that make the profile unusable,
/// or `Ok(warnings)` for non-fatal concerns.
pub fn validate_profile(profile: &Profile) -> Result<Vec<Warning>, ProfileError> {
    let mut warnings = Vec::new();

    // Name must not be empty.
    if profile.name.is_empty() {
        return Err(ProfileError::Validation(
            "profile name cannot be empty".into(),
        ));
    }

    // Callback interval must be positive.
    if profile.timing.callback_interval == 0 {
        return Err(ProfileError::Validation(
            "timing.callback_interval must be > 0".into(),
        ));
    }

    // Jitter percent in valid range.
    if profile.timing.jitter_percent < 0.0 || profile.timing.jitter_percent > 100.0 {
        return Err(ProfileError::Validation(
            "timing.jitter_percent must be between 0 and 100".into(),
        ));
    }

    // HTTP request must have at least one URI pattern.
    if profile.http.request.uri_patterns.is_empty() {
        return Err(ProfileError::Validation(
            "http.request.uri_patterns must contain at least one URI".into(),
        ));
    }

    // Warn if no data embed points defined.
    if profile.http.request.data_embed_points.is_empty() {
        warnings.push(Warning {
            field: "http.request.data_embed_points".into(),
            message: "no data embed points defined; payload data will not be embedded in requests"
                .into(),
        });
    }

    if profile.http.response.data_embed_points.is_empty() {
        warnings.push(Warning {
            field: "http.response.data_embed_points".into(),
            message: "no data embed points defined; response data extraction will fail".into(),
        });
    }

    // Validate working hours if specified.
    if let Some(wh) = &profile.timing.working_hours {
        if wh.start_hour >= 24 || wh.end_hour >= 24 {
            return Err(ProfileError::Validation(
                "working_hours start/end must be 0-23".into(),
            ));
        }
        if wh.off_hours_multiplier <= 0.0 {
            return Err(ProfileError::Validation(
                "working_hours.off_hours_multiplier must be > 0".into(),
            ));
        }
    }

    // Validate burst windows.
    for (i, bw) in profile.timing.burst_windows.iter().enumerate() {
        if bw.start_hour >= 24 || bw.end_hour >= 24 {
            return Err(ProfileError::Validation(format!(
                "burst_windows[{i}] start/end must be 0-23"
            )));
        }
        if bw.interval_override == 0 {
            return Err(ProfileError::Validation(format!(
                "burst_windows[{i}].interval_override must be > 0"
            )));
        }
    }

    // Warn if TLS config is empty.
    if profile.tls.cipher_suites.is_empty() && profile.tls.target_ja3.is_none() {
        warnings.push(Warning {
            field: "tls".into(),
            message: "no cipher suites or target JA3 specified; TLS fingerprint will be default"
                .into(),
        });
    }

    // Warn on large jitter.
    if profile.timing.jitter_percent > 50.0 {
        warnings.push(Warning {
            field: "timing.jitter_percent".into(),
            message: format!(
                "jitter of {}% is unusually high; may cause erratic callback patterns",
                profile.timing.jitter_percent
            ),
        });
    }

    // Validate error_rate if set.
    if let Some(rate) = profile.http.response.error_rate_percent {
        if !(0.0..=100.0).contains(&rate) {
            return Err(ProfileError::Validation(
                "http.response.error_rate_percent must be between 0 and 100".into(),
            ));
        }
    }

    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_yaml() -> &'static str {
        r#"
name: test-profile
description: Minimal test profile
tls:
  cipher_suites: ["TLS_AES_128_GCM_SHA256"]
  alpn: ["h2"]
http:
  request:
    method: POST
    uri_patterns: ["/api/test"]
    headers:
      - name: Content-Type
        value: application/json
    body_template: '{"data": "{{data}}"}'
    data_embed_points:
      - location: json_field
        field_name: data
  response:
    status_code: 200
    body_template: '{"ok": true, "result": "{{data}}"}'
    data_embed_points:
      - location: json_field
        field_name: result
timing:
  callback_interval: 30
  jitter_distribution: uniform
  jitter_percent: 20
transform:
  compress: none
  encrypt: chacha20-poly1305
  encode: base64
"#
    }

    #[test]
    fn test_parse_minimal_profile() {
        let profile = parse_profile(minimal_yaml()).unwrap();
        assert_eq!(profile.name, "test-profile");
        assert_eq!(profile.timing.callback_interval, 30);
        assert_eq!(profile.http.request.uri_patterns.len(), 1);
    }

    #[test]
    fn test_validate_valid_profile() {
        let profile = parse_profile(minimal_yaml()).unwrap();
        let warnings = validate_profile(&profile).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_empty_name() {
        let yaml = r#"
name: ""
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: ["/test"]
  response: {}
timing:
  callback_interval: 10
transform: {}
"#;
        let profile = parse_profile(yaml).unwrap();
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.to_string().contains("name cannot be empty"));
    }

    #[test]
    fn test_validate_zero_interval() {
        let yaml = r#"
name: bad
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: ["/test"]
  response: {}
timing:
  callback_interval: 0
transform: {}
"#;
        let profile = parse_profile(yaml).unwrap();
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.to_string().contains("callback_interval must be > 0"));
    }

    #[test]
    fn test_validate_invalid_jitter() {
        let yaml = r#"
name: bad
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: ["/test"]
  response: {}
timing:
  callback_interval: 10
  jitter_percent: 150
transform: {}
"#;
        let profile = parse_profile(yaml).unwrap();
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.to_string().contains("jitter_percent"));
    }

    #[test]
    fn test_validate_no_uri_patterns() {
        let yaml = r#"
name: bad
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: []
  response: {}
timing:
  callback_interval: 10
transform: {}
"#;
        let profile = parse_profile(yaml).unwrap();
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.to_string().contains("uri_patterns"));
    }

    #[test]
    fn test_validate_warns_no_embed_points() {
        let yaml = r#"
name: sparse
tls: { cipher_suites: ["TLS_AES_256"] }
http:
  request:
    uri_patterns: ["/api/v1"]
  response: {}
timing:
  callback_interval: 30
transform: {}
"#;
        let profile = parse_profile(yaml).unwrap();
        let warnings = validate_profile(&profile).unwrap();
        assert!(warnings.len() >= 2); // both request and response embed point warnings
    }

    #[test]
    fn test_validate_high_jitter_warning() {
        let yaml = r#"
name: jittery
tls: { cipher_suites: ["TLS_AES_256"] }
http:
  request:
    uri_patterns: ["/api"]
    data_embed_points:
      - location: json_field
        field_name: data
  response:
    data_embed_points:
      - location: json_field
        field_name: result
timing:
  callback_interval: 30
  jitter_percent: 75
transform: {}
"#;
        let profile = parse_profile(yaml).unwrap();
        let warnings = validate_profile(&profile).unwrap();
        assert!(warnings
            .iter()
            .any(|w| w.message.contains("unusually high")));
    }

    #[test]
    fn test_parse_invalid_yaml() {
        let result = parse_profile("not: [valid: yaml: {{");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_invalid_working_hours() {
        let yaml = r#"
name: bad-hours
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: ["/api"]
  response: {}
timing:
  callback_interval: 30
  working_hours:
    start_hour: 25
    end_hour: 18
    off_hours_multiplier: 4.0
transform: {}
"#;
        let profile = parse_profile(yaml).unwrap();
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.to_string().contains("0-23"));
    }

    #[test]
    fn test_validate_invalid_error_rate() {
        let yaml = r#"
name: bad-rate
tls: { cipher_suites: [] }
http:
  request:
    uri_patterns: ["/api"]
  response:
    error_rate_percent: 150.0
timing:
  callback_interval: 30
transform: {}
"#;
        let profile = parse_profile(yaml).unwrap();
        let err = validate_profile(&profile).unwrap_err();
        assert!(err.to_string().contains("error_rate_percent"));
    }
}
