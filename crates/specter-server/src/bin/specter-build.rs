//! SPECTER Payload Builder CLI
//!
//! Standalone tool to test the obfuscation pipeline without running the
//! full teamserver. Reads a PIC blob, applies obfuscation transforms,
//! scrubs markers, and writes the result.
//!
//! Usage:
//!   specter-build --pic implant/build/specter.bin --out payload.bin
//!   specter-build --pic implant/build/specter.bin --dump-markers
//!   specter-build --pic implant/build/specter.bin --no-obfuscate --dump-markers

use clap::Parser;
use specter_server::builder::{
    self, scan_payload, ObfuscationSettings,
};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "specter-build", about = "SPECTER Payload Builder CLI — obfuscation pipeline test")]
struct Cli {
    /// Path to the PIC blob (specter.bin)
    #[arg(long, required = true)]
    pic: PathBuf,

    /// Output file path
    #[arg(long, short, default_value = "payload.bin")]
    out: PathBuf,

    /// YARA rules directory
    #[arg(long, default_value = "rules")]
    rules_dir: PathBuf,

    /// Disable all obfuscation transforms
    #[arg(long)]
    no_obfuscate: bool,

    /// Enable XOR encryption wrapper
    #[arg(long)]
    xor: bool,

    /// Dump diagnostic info about remaining markers
    #[arg(long)]
    dump_markers: bool,

    /// Only run marker scan (no output file)
    #[arg(long)]
    scan_only: bool,
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

fn main() {
    let cli = Cli::parse();

    // Read PIC blob
    let pic_data = match std::fs::read(&cli.pic) {
        Ok(data) => {
            println!("[+] Loaded: {} ({} bytes)", cli.pic.display(), data.len());
            data
        }
        Err(e) => {
            eprintln!("[-] Failed to read {}: {e}", cli.pic.display());
            std::process::exit(1);
        }
    };

    // Pre-obfuscation marker scan
    if cli.dump_markers || cli.scan_only {
        println!("\n[*] Pre-obfuscation markers:");
        let markers = scan_for_markers(&pic_data);
        if markers.is_empty() {
            println!("    None found");
        } else {
            for (offset, name) in &markers {
                println!("    {} at 0x{:06X}", name, offset);
            }
            println!("    Total: {}", markers.len());
        }
    }

    // Apply obfuscation transforms
    let mut blob = pic_data;

    if !cli.no_obfuscate {
        let settings = ObfuscationSettings {
            xor_encryption: false, // applied separately
            ..ObfuscationSettings::default()
        };

        println!("\n[*] Applying obfuscation transforms...");
        let pre_size = blob.len();
        match builder::apply_transforms(&mut blob, &settings) {
            Ok(()) => {
                let post_size = blob.len();
                println!("    String encryption: applied");
                println!("    API hash randomization: applied");
                println!("    Junk code insertion: applied");
                if pre_size != post_size {
                    println!("    WARNING: blob size changed {} -> {} (SHOULD NOT HAPPEN)", pre_size, post_size);
                } else {
                    println!("    Blob size unchanged: {} bytes (correct)", post_size);
                }
            }
            Err(e) => {
                println!("    Transform error: {e}");
                println!("    Continuing with untransformed blob...");
            }
        }
    } else {
        println!("\n[*] Obfuscation disabled");
    }

    // Scrub markers (simulating finalize_payload)
    println!("\n[*] Scrubbing markers...");
    builder::finalize_payload(&mut blob);

    // Post-scrub marker scan
    if cli.dump_markers || cli.scan_only {
        println!("\n[*] Post-scrub markers:");
        let markers = scan_for_markers(&blob);
        if markers.is_empty() {
            println!("    None found (clean!)");
        } else {
            for (offset, name) in &markers {
                println!("    REMAINING: {} at 0x{:06X}", name, offset);
            }
            println!("    {} markers still present", markers.len());
        }
    }

    // XOR encryption
    if cli.xor {
        println!("\n[*] Applying XOR encryption wrapper...");
        let settings = ObfuscationSettings {
            xor_encryption: true,
            ..Default::default()
        };
        match builder::obfuscate_blob(&blob, &settings) {
            Ok(wrapped) => {
                println!("    Wrapped: {} -> {} bytes", blob.len(), wrapped.len());
                blob = wrapped;
            }
            Err(e) => println!("    XOR failed: {e}"),
        }
    }

    // YARA scan
    if cli.rules_dir.exists() {
        println!("\n[*] YARA scan ({}):", cli.rules_dir.display());
        match scan_payload(&blob, &cli.rules_dir) {
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
    match std::fs::write(&cli.out, &blob) {
        Ok(()) => println!("\n[+] Written to {} ({} bytes)", cli.out.display(), blob.len()),
        Err(e) => {
            eprintln!("[-] Write failed: {e}");
            std::process::exit(1);
        }
    }
}
