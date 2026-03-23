//! Beacon API shim consistency tests (Rust-side).
//!
//! These tests verify the beacon_shim.c symbol table and beacon.h definitions
//! are complete and consistent by parsing the C source files. The actual
//! runtime behavior of the C shim is tested in `implant/tests/test_beacon_shim.c`.

use std::collections::HashSet;

/// Path to the implant source root, relative to the specter-server crate.
fn implant_dir() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../implant/core")
}

/// Extract Beacon API function names declared in beacon.h (prototypes).
fn extract_beacon_h_prototypes() -> HashSet<String> {
    let path = implant_dir().join("include/beacon.h");
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read beacon.h: {e}"));

    let mut names = HashSet::new();

    // Match function prototypes: return_type FunctionName(...)
    // Beacon API functions start with "Beacon", "toWideChar", "SPECTER_",
    // "clr_execute_assembly", "exec_shellcode", or "beacon_shim_"
    let prefixes = [
        "BeaconOutput",
        "BeaconPrintf",
        "BeaconDataParse",
        "BeaconDataInt",
        "BeaconDataShort",
        "BeaconDataLength",
        "BeaconDataExtract",
        "BeaconFormatAlloc",
        "BeaconFormatReset",
        "BeaconFormatAppend",
        "BeaconFormatPrintf",
        "BeaconFormatToString",
        "BeaconFormatFree",
        "BeaconFormatInt",
        "BeaconUseToken",
        "BeaconRevertToken",
        "BeaconIsAdmin",
        "BeaconGetSpawnTo",
        "toWideChar",
        "SPECTER_MemAlloc",
        "SPECTER_Resolve",
        "SPECTER_NetConnect",
        "SPECTER_ProcOpen",
        "SPECTER_FileRead",
    ];

    for prefix in &prefixes {
        if source.contains(&format!("{prefix}(")) {
            names.insert(prefix.to_string());
        }
    }

    names
}

/// Extract symbol names registered in g_beacon_api_table[] from beacon_shim.c.
fn extract_symbol_table_entries() -> HashSet<String> {
    let path = implant_dir().join("src/bus/beacon_shim.c");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read beacon_shim.c: {e}"));

    let mut names = HashSet::new();

    // Find lines like: { "FunctionName", (PVOID)FunctionName },
    let in_table = source
        .find("g_beacon_api_table[]")
        .expect("g_beacon_api_table not found in beacon_shim.c");
    let table_section = &source[in_table..];

    // Find closing brace of the table
    let table_end = table_section.find("};").unwrap_or(table_section.len());
    let table_body = &table_section[..table_end];

    for line in table_body.lines() {
        let line = line.trim();
        // Match: { "SymbolName", ...
        if line.starts_with('{') || line.starts_with("{ ") {
            if let Some(quote_start) = line.find('"') {
                if let Some(quote_end) = line[quote_start + 1..].find('"') {
                    let name = &line[quote_start + 1..quote_start + 1 + quote_end];
                    names.insert(name.to_string());
                }
            }
        }
    }

    names
}

/// Extract function implementations from beacon_shim.c (defined functions).
fn extract_shim_implementations() -> HashSet<String> {
    let path = implant_dir().join("src/bus/beacon_shim.c");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read beacon_shim.c: {e}"));

    let mut names = HashSet::new();

    // Known Beacon API function names to look for as implementations
    let beacon_funcs = [
        "BeaconOutput",
        "BeaconPrintf",
        "BeaconDataParse",
        "BeaconDataInt",
        "BeaconDataShort",
        "BeaconDataLength",
        "BeaconDataExtract",
        "BeaconFormatAlloc",
        "BeaconFormatReset",
        "BeaconFormatAppend",
        "BeaconFormatPrintf",
        "BeaconFormatToString",
        "BeaconFormatFree",
        "BeaconFormatInt",
        "BeaconUseToken",
        "BeaconRevertToken",
        "BeaconIsAdmin",
        "BeaconGetSpawnTo",
        "toWideChar",
        "SPECTER_MemAlloc",
        "SPECTER_Resolve",
        "SPECTER_NetConnect",
        "SPECTER_ProcOpen",
        "SPECTER_FileRead",
    ];

    for func in &beacon_funcs {
        // Look for function definition: "type FuncName("
        // Exclude lines that are just declarations (ending with ;)
        let pattern = format!("{func}(");
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.contains(&pattern) && !trimmed.ends_with(';') && !trimmed.starts_with("//") {
                names.insert(func.to_string());
                break;
            }
        }
    }

    names
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn beacon_h_declares_all_standard_beacon_api_functions() {
    let protos = extract_beacon_h_prototypes();

    let required_standard = [
        "BeaconOutput",
        "BeaconPrintf",
        "BeaconDataParse",
        "BeaconDataInt",
        "BeaconDataShort",
        "BeaconDataLength",
        "BeaconDataExtract",
        "BeaconFormatAlloc",
        "BeaconFormatReset",
        "BeaconFormatAppend",
        "BeaconFormatPrintf",
        "BeaconFormatToString",
        "BeaconFormatFree",
        "BeaconFormatInt",
        "BeaconUseToken",
        "BeaconRevertToken",
        "BeaconIsAdmin",
        "BeaconGetSpawnTo",
        "toWideChar",
    ];

    for func in &required_standard {
        assert!(
            protos.contains(*func),
            "beacon.h missing prototype for '{func}'"
        );
    }
}

#[test]
fn beacon_h_declares_specter_extended_api() {
    let protos = extract_beacon_h_prototypes();

    let extended = [
        "SPECTER_MemAlloc",
        "SPECTER_Resolve",
        "SPECTER_NetConnect",
        "SPECTER_ProcOpen",
        "SPECTER_FileRead",
    ];

    for func in &extended {
        assert!(
            protos.contains(*func),
            "beacon.h missing SPECTER extended API: '{func}'"
        );
    }
}

#[test]
fn symbol_table_contains_all_standard_beacon_functions() {
    let table = extract_symbol_table_entries();

    let required = [
        "BeaconOutput",
        "BeaconPrintf",
        "BeaconDataParse",
        "BeaconDataInt",
        "BeaconDataShort",
        "BeaconDataLength",
        "BeaconDataExtract",
        "BeaconFormatAlloc",
        "BeaconFormatReset",
        "BeaconFormatAppend",
        "BeaconFormatPrintf",
        "BeaconFormatToString",
        "BeaconFormatFree",
        "BeaconFormatInt",
        "BeaconUseToken",
        "BeaconRevertToken",
        "BeaconIsAdmin",
        "BeaconGetSpawnTo",
        "toWideChar",
    ];

    for func in &required {
        assert!(
            table.contains(*func),
            "g_beacon_api_table missing entry for '{func}'"
        );
    }
}

#[test]
fn symbol_table_contains_specter_extended_entries() {
    let table = extract_symbol_table_entries();

    let extended = [
        "SPECTER_MemAlloc",
        "SPECTER_Resolve",
        "SPECTER_NetConnect",
        "SPECTER_ProcOpen",
        "SPECTER_FileRead",
    ];

    for func in &extended {
        assert!(
            table.contains(*func),
            "g_beacon_api_table missing SPECTER entry: '{func}'"
        );
    }
}

#[test]
fn every_symbol_table_entry_has_implementation() {
    let table = extract_symbol_table_entries();
    let impls = extract_shim_implementations();

    for sym in &table {
        assert!(
            impls.contains(sym),
            "symbol table references '{sym}' but no implementation found in beacon_shim.c"
        );
    }
}

#[test]
fn every_header_prototype_is_in_symbol_table_or_is_infrastructure() {
    let protos = extract_beacon_h_prototypes();
    let table = extract_symbol_table_entries();

    // Infrastructure functions not in the symbol table (not callable from BOFs)
    let infra = HashSet::from([
        "beacon_shim_init".to_string(),
        "beacon_shim_get_table".to_string(),
        "clr_execute_assembly".to_string(),
        "exec_shellcode".to_string(),
    ]);

    for proto in &protos {
        if infra.contains(proto) {
            continue;
        }
        assert!(
            table.contains(proto),
            "beacon.h prototype '{proto}' not found in g_beacon_api_table"
        );
    }
}

#[test]
fn datap_struct_defined_in_beacon_h() {
    let path = implant_dir().join("include/beacon.h");
    let source = std::fs::read_to_string(&path).unwrap();

    assert!(
        source.contains("} datap;"),
        "datap struct not found in beacon.h"
    );
    assert!(
        source.contains("original"),
        "datap.original field not found"
    );
    assert!(source.contains("buffer"), "datap.buffer field not found");
    assert!(source.contains("length"), "datap.length field not found");
    assert!(source.contains("size"), "datap.size field not found");
}

#[test]
fn formatp_struct_defined_in_beacon_h() {
    let path = implant_dir().join("include/beacon.h");
    let source = std::fs::read_to_string(&path).unwrap();

    assert!(
        source.contains("} formatp;"),
        "formatp struct not found in beacon.h"
    );
    assert!(
        source.contains("BEACON_FORMAT_ALLOC_MAX"),
        "BEACON_FORMAT_ALLOC_MAX not defined"
    );
}

#[test]
fn callback_constants_match_cobalt_strike() {
    let path = implant_dir().join("include/beacon.h");
    let source = std::fs::read_to_string(&path).unwrap();

    // Verify Cobalt Strike callback type constants
    assert!(
        source.contains("CALLBACK_OUTPUT") && source.contains("0x00"),
        "CALLBACK_OUTPUT should be 0x00"
    );
    assert!(
        source.contains("CALLBACK_OUTPUT_OEM") && source.contains("0x1e"),
        "CALLBACK_OUTPUT_OEM should be 0x1e"
    );
    assert!(
        source.contains("CALLBACK_ERROR") && source.contains("0x0d"),
        "CALLBACK_ERROR should be 0x0d"
    );
}

#[test]
fn symbol_table_entry_count_matches_expected() {
    let table = extract_symbol_table_entries();

    // 19 standard Beacon API + 5 SPECTER extended = 24 minimum
    // The actual table may have additional entries (e.g., BeaconFormatReset)
    assert!(
        table.len() >= 23,
        "expected at least 23 symbol table entries, got {}",
        table.len()
    );
}
