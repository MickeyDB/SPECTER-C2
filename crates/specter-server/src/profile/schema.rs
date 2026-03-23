use serde::Deserialize;

/// Top-level malleable C2 profile.
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub tls: TlsConfig,
    pub http: HttpConfig,
    pub timing: TimingConfig,
    pub transform: TransformChain,
}

/// TLS fingerprint configuration for JA3 targeting.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub cipher_suites: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub curves: Vec<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub target_ja3: Option<String>,
}

/// HTTP transaction shaping configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    pub request: HttpTemplate,
    pub response: HttpTemplate,
    #[serde(default)]
    pub uri_rotation: UriRotation,
    #[serde(default)]
    pub cookie_config: Option<CookieConfig>,
}

/// URI rotation mode.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UriRotation {
    #[default]
    Sequential,
    Random,
    RoundRobin,
}

/// Cookie shaping configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CookieConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub attributes: Vec<String>,
}

/// HTTP request or response template.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpTemplate {
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub uri_patterns: Vec<String>,
    #[serde(default)]
    pub headers: Vec<HeaderEntry>,
    #[serde(default)]
    pub body_template: Option<String>,
    #[serde(default)]
    pub data_embed_points: Vec<EmbedPoint>,
    #[serde(default)]
    pub status_code: Option<u16>,
    #[serde(default)]
    pub error_rate_percent: Option<f64>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// Ordered header entry with template variable support.
#[derive(Debug, Clone, Deserialize)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

/// Data embed point — where payload data is placed in the HTTP transaction.
#[derive(Debug, Clone, Deserialize)]
pub struct EmbedPoint {
    pub location: EmbedLocation,
    #[serde(default)]
    pub field_name: Option<String>,
    #[serde(default)]
    pub encoding: Option<EmbedEncoding>,
}

/// Where in the HTTP transaction to embed data.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbedLocation {
    JsonField,
    CookieValue,
    UriSegment,
    QueryParam,
    MultipartField,
    HeaderValue,
}

/// Encoding applied to embedded data at a specific point.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbedEncoding {
    Base64,
    Hex,
    Raw,
}

/// Callback timing and jitter configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct TimingConfig {
    /// Callback interval in seconds.
    pub callback_interval: u64,
    #[serde(default)]
    pub jitter_distribution: JitterDistribution,
    /// Jitter percentage (0-100).
    #[serde(default = "default_jitter")]
    pub jitter_percent: f64,
    #[serde(default)]
    pub working_hours: Option<WorkingHours>,
    #[serde(default)]
    pub burst_windows: Vec<BurstWindow>,
    /// Initial delay before first callback, in seconds.
    #[serde(default)]
    pub initial_delay: u64,
}

fn default_jitter() -> f64 {
    10.0
}

/// Jitter distribution model.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum JitterDistribution {
    #[default]
    Uniform,
    Gaussian,
    Pareto,
    Empirical,
}

/// Working hours window.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkingHours {
    pub start_hour: u8,
    pub end_hour: u8,
    #[serde(default)]
    pub days: Vec<String>,
    /// Multiplier applied to callback interval outside working hours.
    #[serde(default = "default_off_hours_multiplier")]
    pub off_hours_multiplier: f64,
}

fn default_off_hours_multiplier() -> f64 {
    1.0
}

/// Burst window for high-frequency callbacks.
#[derive(Debug, Clone, Deserialize)]
pub struct BurstWindow {
    pub start_hour: u8,
    pub end_hour: u8,
    pub interval_override: u64,
}

/// Payload transform chain: compress → encrypt → encode.
#[derive(Debug, Clone, Deserialize)]
pub struct TransformChain {
    #[serde(default)]
    pub compress: Compression,
    /// Encryption is always ChaCha20-Poly1305; this field is informational.
    #[serde(default)]
    pub encrypt: Encryption,
    #[serde(default)]
    pub encode: Encoding,
}

/// Compression algorithm.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    #[default]
    None,
    Lz4,
    Zstd,
}

/// Encryption algorithm (only ChaCha20-Poly1305 supported).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Encryption {
    #[default]
    #[serde(alias = "chacha20-poly1305")]
    ChaCha20Poly1305,
}

/// Output encoding after encryption.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    #[default]
    Base64,
    Base85,
    Hex,
    Raw,
    CustomAlphabet,
}
