/**
 * SPECTER Implant — Module Loader Test Suite
 *
 * Tests for:
 *   - MODULE_PACKAGE header parsing and validation
 *   - Ed25519 signature verification of module packages
 *   - COFF header parsing, section layout, relocation processing
 *   - Symbol resolution (bus API names, Beacon shims, DLL$Func format)
 *   - PIC loader API table injection
 *
 * Build: gcc -o test_coff_loader test_coff_loader.c
 *            ../core/src/bus/loader.c ../core/src/crypto.c
 *            ../core/src/crypto_sign.c ../core/src/string.c
 *            ../core/src/hash.c -I../core/include -DTEST_BUILD
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "specter.h"
#include "crypto.h"

/* Provide definition for g_ctx */
IMPLANT_CONTEXT g_ctx;

/* Stubs for PEB functions */
PPEB    get_peb(void) { return NULL; }
PVOID   find_module_by_hash(DWORD hash) { (void)hash; return NULL; }
PVOID   find_export_by_hash(PVOID base, DWORD hash) { (void)base; (void)hash; return NULL; }
PVOID   resolve_function(DWORD mh, DWORD fh) { (void)mh; (void)fh; return NULL; }

/* ------------------------------------------------------------------ */
/*  Include bus.h (needs all the types above)                          */
/* ------------------------------------------------------------------ */

#include "bus.h"

/* ------------------------------------------------------------------ */
/*  Mock memory allocator for bus API                                  */
/* ------------------------------------------------------------------ */

#define MOCK_ALLOC_MAX  16
static struct {
    PVOID  base;
    SIZE_T size;
    DWORD  protect;
} mock_allocs[MOCK_ALLOC_MAX];
static int mock_alloc_count = 0;

static PVOID mock_mem_alloc(SIZE_T size, DWORD perms) {
    if (mock_alloc_count >= MOCK_ALLOC_MAX)
        return NULL;
    PVOID p = calloc(1, (size_t)size);
    if (p) {
        mock_allocs[mock_alloc_count].base = p;
        mock_allocs[mock_alloc_count].size = size;
        mock_allocs[mock_alloc_count].protect = perms;
        mock_alloc_count++;
    }
    return p;
}

static BOOL mock_mem_free(PVOID ptr) {
    if (!ptr) return FALSE;
    for (int i = 0; i < mock_alloc_count; i++) {
        if (mock_allocs[i].base == ptr) {
            free(ptr);
            mock_allocs[i] = mock_allocs[mock_alloc_count - 1];
            mock_alloc_count--;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL mock_mem_protect(PVOID ptr, SIZE_T size, DWORD perms) {
    (void)size;
    for (int i = 0; i < mock_alloc_count; i++) {
        if (mock_allocs[i].base == ptr) {
            mock_allocs[i].protect = perms;
            return TRUE;
        }
    }
    /* Also succeed for sub-region protections */
    for (int i = 0; i < mock_alloc_count; i++) {
        BYTE *base = (BYTE *)mock_allocs[i].base;
        BYTE *end = base + mock_allocs[i].size;
        if ((BYTE *)ptr >= base && (BYTE *)ptr < end) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL mock_output(const BYTE *data, DWORD len, DWORD type) {
    (void)data; (void)len; (void)type;
    return TRUE;
}

static PVOID mock_resolve(const char *dll_name, const char *func_name) {
    (void)dll_name; (void)func_name;
    /* Return a non-NULL "resolved" address for testing */
    static BYTE fake_func = 0xC3;  /* ret */
    return &fake_func;
}

static void mock_log(DWORD level, const char *msg) {
    (void)level; (void)msg;
}

static void mock_cleanup(void) {
    for (int i = 0; i < mock_alloc_count; i++) {
        free(mock_allocs[i].base);
    }
    mock_alloc_count = 0;
}

/* Null stubs for unused bus API functions */
static HANDLE mock_null_handle(void) { return NULL; }
static BOOL mock_false(void) { return FALSE; }
static DWORD mock_zero(void) { return 0; }

static MODULE_BUS_API *create_mock_api(void) {
    static MODULE_BUS_API api;
    memset(&api, 0, sizeof(api));

    api.mem_alloc   = mock_mem_alloc;
    api.mem_free    = mock_mem_free;
    api.mem_protect = mock_mem_protect;
    api.output      = mock_output;
    api.resolve     = mock_resolve;
    api.log         = mock_log;

    /* Fill remaining with safe stubs */
    api.net_connect = (HANDLE(*)(const char*,DWORD,DWORD))mock_null_handle;
    api.net_send    = (BOOL(*)(HANDLE,const BYTE*,DWORD))mock_false;
    api.net_recv    = (DWORD(*)(HANDLE,BYTE*,DWORD))mock_zero;
    api.net_close   = (BOOL(*)(HANDLE))mock_false;
    api.proc_open   = (HANDLE(*)(DWORD,DWORD))mock_null_handle;
    api.proc_read   = (BOOL(*)(HANDLE,PVOID,BYTE*,DWORD))mock_false;
    api.proc_write  = (BOOL(*)(HANDLE,PVOID,const BYTE*,DWORD))mock_false;
    api.proc_close  = (BOOL(*)(HANDLE))mock_false;
    api.thread_create = (HANDLE(*)(PVOID,PVOID,BOOL))mock_null_handle;
    api.thread_resume = (BOOL(*)(HANDLE))mock_false;
    api.thread_terminate = (BOOL(*)(HANDLE))mock_false;
    api.token_steal = (HANDLE(*)(DWORD))mock_null_handle;
    api.token_impersonate = (BOOL(*)(HANDLE))mock_false;
    api.token_revert = (BOOL(*)(void))mock_false;
    api.token_make  = (HANDLE(*)(const char*,const char*,const char*))mock_null_handle;
    api.file_read   = (DWORD(*)(const char*,BYTE*,DWORD))mock_zero;
    api.file_write  = (BOOL(*)(const char*,const BYTE*,DWORD))mock_false;
    api.file_delete = (BOOL(*)(const char*))mock_false;
    api.file_list   = (PVOID(*)(const char*))mock_null_handle;
    api.reg_read    = (DWORD(*)(DWORD,const char*,const char*))mock_zero;
    api.reg_write   = (BOOL(*)(DWORD,const char*,const char*,const BYTE*,DWORD))mock_false;
    api.reg_delete  = (BOOL(*)(DWORD,const char*,const char*))mock_false;

    return &api;
}

/* ------------------------------------------------------------------ */
/*  Test infrastructure                                                */
/* ------------------------------------------------------------------ */

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [TEST] %-55s ", name); \
} while(0)

#define PASS() do { tests_passed++; printf("[PASS]\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("[FAIL] %s\n", msg); } while(0)

/* ------------------------------------------------------------------ */
/*  Helper: build a minimal MODULE_PACKAGE header                      */
/* ------------------------------------------------------------------ */

static void build_package_header(BYTE *buf, DWORD module_type,
                                  DWORD encrypted_size) {
    MODULE_PACKAGE_HDR *hdr = (MODULE_PACKAGE_HDR *)buf;
    hdr->magic = MODULE_MAGIC;
    hdr->version = MODULE_VERSION;
    hdr->module_type = module_type;
    hdr->encrypted_size = encrypted_size;
    memset(hdr->ephemeral_pubkey, 0xAA, 32);
    memset(hdr->signature, 0xBB, 64);
}

/* ------------------------------------------------------------------ */
/*  Helper: build a minimal COFF object file in memory                 */
/* ------------------------------------------------------------------ */

/*
 * Creates a minimal COFF with:
 *   - File header
 *   - 1 section (.text) with a small code blob
 *   - Symbol table with "go" entry
 *   - Optionally: relocations
 */

typedef struct {
    BYTE *data;
    DWORD size;
} COFF_BLOB;

static COFF_BLOB build_minimal_coff(void) {
    /* Layout:
     * [0]    COFF_FILE_HEADER  (20 bytes)
     * [20]   COFF_SECTION      (40 bytes) — .text
     * [60]   Section data      (16 bytes) — simple code
     * [76]   COFF_SYMBOL       (18 bytes) — "go" symbol
     * [94]   String table      (4 bytes)  — size only (no long names)
     */
    DWORD file_hdr_size = 20;  /* sizeof(COFF_FILE_HEADER) packed */
    DWORD sec_hdr_size  = 40;  /* sizeof(COFF_SECTION) packed */
    DWORD code_size     = 16;
    DWORD sym_size      = 18;  /* sizeof(COFF_SYMBOL) packed */
    DWORD strtab_size   = 4;   /* Just the size field */

    DWORD code_offset   = file_hdr_size + sec_hdr_size;
    DWORD sym_offset    = code_offset + code_size;
    DWORD total         = sym_offset + sym_size + strtab_size;

    BYTE *buf = (BYTE *)calloc(1, total);
    if (!buf) return (COFF_BLOB){NULL, 0};

    /* File header */
    COFF_FILE_HEADER *fh = (COFF_FILE_HEADER *)buf;
    fh->Machine = IMAGE_FILE_MACHINE_AMD64;
    fh->NumberOfSections = 1;
    fh->PointerToSymbolTable = sym_offset;
    fh->NumberOfSymbols = 1;
    fh->SizeOfOptionalHeader = 0;

    /* Section header: .text */
    COFF_SECTION *sec = (COFF_SECTION *)(buf + file_hdr_size);
    memcpy(sec->Name, ".text\0\0\0", 8);
    sec->SizeOfRawData = code_size;
    sec->PointerToRawData = code_offset;
    sec->Characteristics = IMAGE_SCN_CNT_CODE |
                           IMAGE_SCN_MEM_EXECUTE |
                           IMAGE_SCN_MEM_READ;

    /* Code data: simple pattern (not real executable, just for test) */
    BYTE code[] = {
        0xCC, 0xCC, 0xCC, 0xCC,  /* int3 padding */
        0x48, 0x89, 0xC8,        /* mov rax, rcx (return first arg) */
        0xC3,                    /* ret */
        0x90, 0x90, 0x90, 0x90,  /* nop padding */
        0x90, 0x90, 0x90, 0x90,
    };
    memcpy(buf + code_offset, code, code_size);

    /* Symbol: "go" at offset 4 in .text (after int3 padding) */
    COFF_SYMBOL *sym = (COFF_SYMBOL *)(buf + sym_offset);
    memcpy(sym->Name.ShortName, "go\0\0\0\0\0\0", 8);
    sym->Value = 4;            /* Offset within section */
    sym->SectionNumber = 1;    /* Section #1 (.text) */
    sym->StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
    sym->NumberOfAuxSymbols = 0;

    /* String table: just the size (4 bytes = empty) */
    DWORD *strtab = (DWORD *)(buf + sym_offset + sym_size);
    *strtab = 4;

    return (COFF_BLOB){buf, total};
}

/*
 * Build a COFF with relocations:
 *   - .text section with a relocation reference
 *   - .data section with target data
 *   - Symbols for both sections + external
 *   - REL32 and ADDR64 relocations
 */
static COFF_BLOB build_coff_with_relocs(void) {
    DWORD fh_size  = 20;
    DWORD sh_size  = 40;
    DWORD num_secs = 2;

    DWORD text_size = 32;
    DWORD data_size = 16;

    DWORD headers_size = fh_size + sh_size * num_secs;
    DWORD text_off = headers_size;
    DWORD data_off = text_off + text_size;

    /* Relocations for .text: 2 entries */
    DWORD reloc_entry_size = 10; /* sizeof(COFF_RELOCATION) packed */
    DWORD num_relocs = 2;
    DWORD reloc_off = data_off + data_size;
    DWORD reloc_total = reloc_entry_size * num_relocs;

    /* Symbols: 3 entries (go, data_sym, external) */
    DWORD sym_entry_size = 18;
    DWORD num_syms = 3;
    DWORD sym_off = reloc_off + reloc_total;
    DWORD strtab_off = sym_off + sym_entry_size * num_syms;
    DWORD strtab_size = 4; /* empty */

    DWORD total = strtab_off + strtab_size;

    BYTE *buf = (BYTE *)calloc(1, total);
    if (!buf) return (COFF_BLOB){NULL, 0};

    /* File header */
    COFF_FILE_HEADER *fh = (COFF_FILE_HEADER *)buf;
    fh->Machine = IMAGE_FILE_MACHINE_AMD64;
    fh->NumberOfSections = (WORD)num_secs;
    fh->PointerToSymbolTable = sym_off;
    fh->NumberOfSymbols = num_syms;

    /* Section 1: .text */
    COFF_SECTION *text_sec = (COFF_SECTION *)(buf + fh_size);
    memcpy(text_sec->Name, ".text\0\0\0", 8);
    text_sec->SizeOfRawData = text_size;
    text_sec->PointerToRawData = text_off;
    text_sec->PointerToRelocations = reloc_off;
    text_sec->NumberOfRelocations = (WORD)num_relocs;
    text_sec->Characteristics = IMAGE_SCN_CNT_CODE |
                                IMAGE_SCN_MEM_EXECUTE |
                                IMAGE_SCN_MEM_READ;

    /* Section 2: .data */
    COFF_SECTION *data_sec = (COFF_SECTION *)(buf + fh_size + sh_size);
    memcpy(data_sec->Name, ".data\0\0\0", 8);
    data_sec->SizeOfRawData = data_size;
    data_sec->PointerToRawData = data_off;
    data_sec->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                IMAGE_SCN_MEM_READ |
                                IMAGE_SCN_MEM_WRITE;

    /* .text code: with relocation slots */
    BYTE text_code[32];
    memset(text_code, 0x90, sizeof(text_code)); /* nops */
    /* At offset 0: entry ("go" at offset 0)
     * At offset 4: REL32 relocation target (4 bytes to be patched)
     * At offset 16: ADDR64 relocation target (8 bytes to be patched) */
    text_code[0] = 0xE8;  /* call rel32 */
    /* bytes [1..4] will be patched by REL32 relocation */
    text_code[1] = 0x00; text_code[2] = 0x00;
    text_code[3] = 0x00; text_code[4] = 0x00;
    text_code[5] = 0xC3;  /* ret */
    /* At offset 16: mov rax, imm64 */
    text_code[16] = 0x48; text_code[17] = 0xB8;
    /* bytes [18..25] will be patched by ADDR64 relocation */
    memcpy(buf + text_off, text_code, text_size);

    /* .data content */
    BYTE data_content[16] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
    };
    memcpy(buf + data_off, data_content, data_size);

    /* Relocations for .text */
    COFF_RELOCATION *relocs = (COFF_RELOCATION *)(buf + reloc_off);
    /* Reloc 1: REL32 at offset 1 referencing data_sym (symbol index 1) */
    relocs[0].VirtualAddress = 1;
    relocs[0].SymbolTableIndex = 1;
    relocs[0].Type = IMAGE_REL_AMD64_REL32;
    /* Reloc 2: ADDR64 at offset 18 referencing data_sym (symbol index 1) */
    relocs[1].VirtualAddress = 18;
    relocs[1].SymbolTableIndex = 1;
    relocs[1].Type = IMAGE_REL_AMD64_ADDR64;

    /* Symbols */
    COFF_SYMBOL *syms = (COFF_SYMBOL *)(buf + sym_off);

    /* Symbol 0: "go" in .text at offset 0 */
    memcpy(syms[0].Name.ShortName, "go\0\0\0\0\0\0", 8);
    syms[0].Value = 0;
    syms[0].SectionNumber = 1;
    syms[0].StorageClass = IMAGE_SYM_CLASS_EXTERNAL;

    /* Symbol 1: "data_sym" — short name fits in 8 bytes */
    memcpy(syms[1].Name.ShortName, "data_sym", 8);
    syms[1].Value = 0;
    syms[1].SectionNumber = 2;
    syms[1].StorageClass = IMAGE_SYM_CLASS_EXTERNAL;

    /* Symbol 2: external (undefined) */
    memcpy(syms[2].Name.ShortName, "ext_func", 8);
    syms[2].Value = 0;
    syms[2].SectionNumber = IMAGE_SYM_UNDEFINED;
    syms[2].StorageClass = IMAGE_SYM_CLASS_EXTERNAL;

    /* String table */
    DWORD *strtab = (DWORD *)(buf + strtab_off);
    *strtab = 4;

    return (COFF_BLOB){buf, total};
}

/* ================================================================== */
/*  Test: MODULE_PACKAGE header parsing                                */
/* ================================================================== */

static void test_parse_header_valid(void) {
    BYTE buf[256];
    memset(buf, 0, sizeof(buf));
    build_package_header(buf, MODULE_TYPE_PIC, 64);

    /* Append fake encrypted data */
    DWORD total = sizeof(MODULE_PACKAGE_HDR) + 64;

    TEST("parse_header valid PIC package");
    const MODULE_PACKAGE_HDR *hdr = loader_parse_header(buf, total);
    if (hdr && hdr->magic == MODULE_MAGIC &&
        hdr->module_type == MODULE_TYPE_PIC &&
        hdr->encrypted_size == 64)
        PASS();
    else
        FAIL("header parsing failed");
}

static void test_parse_header_coff(void) {
    BYTE buf[256];
    memset(buf, 0, sizeof(buf));
    build_package_header(buf, MODULE_TYPE_COFF, 100);
    DWORD total = sizeof(MODULE_PACKAGE_HDR) + 100;

    TEST("parse_header valid COFF package");
    const MODULE_PACKAGE_HDR *hdr = loader_parse_header(buf, total);
    if (hdr && hdr->module_type == MODULE_TYPE_COFF)
        PASS();
    else
        FAIL("COFF header parsing failed");
}

static void test_parse_header_bad_magic(void) {
    BYTE buf[256];
    memset(buf, 0, sizeof(buf));
    build_package_header(buf, MODULE_TYPE_PIC, 64);
    /* Corrupt magic */
    buf[0] = 0xFF;
    DWORD total = sizeof(MODULE_PACKAGE_HDR) + 64;

    TEST("parse_header rejects bad magic");
    if (loader_parse_header(buf, total) == NULL)
        PASS();
    else
        FAIL("bad magic accepted");
}

static void test_parse_header_bad_version(void) {
    BYTE buf[256];
    memset(buf, 0, sizeof(buf));
    build_package_header(buf, MODULE_TYPE_PIC, 64);
    /* Corrupt version */
    MODULE_PACKAGE_HDR *hdr = (MODULE_PACKAGE_HDR *)buf;
    hdr->version = 99;
    DWORD total = sizeof(MODULE_PACKAGE_HDR) + 64;

    TEST("parse_header rejects bad version");
    if (loader_parse_header(buf, total) == NULL)
        PASS();
    else
        FAIL("bad version accepted");
}

static void test_parse_header_bad_type(void) {
    BYTE buf[256];
    memset(buf, 0, sizeof(buf));
    build_package_header(buf, 42, 64);
    DWORD total = sizeof(MODULE_PACKAGE_HDR) + 64;

    TEST("parse_header rejects bad module type");
    if (loader_parse_header(buf, total) == NULL)
        PASS();
    else
        FAIL("bad type accepted");
}

static void test_parse_header_truncated(void) {
    BYTE buf[256];
    memset(buf, 0, sizeof(buf));
    build_package_header(buf, MODULE_TYPE_PIC, 64);

    TEST("parse_header rejects truncated package");
    /* Pass less data than header claims */
    if (loader_parse_header(buf, sizeof(MODULE_PACKAGE_HDR) + 10) == NULL)
        PASS();
    else
        FAIL("truncated package accepted");
}

static void test_parse_header_null(void) {
    TEST("parse_header rejects NULL");
    if (loader_parse_header(NULL, 100) == NULL)
        PASS();
    else
        FAIL("NULL accepted");
}

static void test_parse_header_too_small(void) {
    BYTE buf[4] = {0};

    TEST("parse_header rejects too-small buffer");
    if (loader_parse_header(buf, 4) == NULL)
        PASS();
    else
        FAIL("too-small buffer accepted");
}

static void test_parse_header_zero_size(void) {
    BYTE buf[256];
    memset(buf, 0, sizeof(buf));
    build_package_header(buf, MODULE_TYPE_PIC, 0);

    TEST("parse_header rejects zero encrypted_size");
    if (loader_parse_header(buf, sizeof(MODULE_PACKAGE_HDR)) == NULL)
        PASS();
    else
        FAIL("zero encrypted_size accepted");
}

/* ================================================================== */
/*  Test: PIC loader                                                   */
/* ================================================================== */

static void test_pic_loader_basic(void) {
    TEST("PIC loader basic load");

    MODULE_BUS_API *api = create_mock_api();
    LOADED_MODULE mod;
    memset(&mod, 0, sizeof(mod));

    /* Build a PIC blob: 8 bytes API pointer slot + code */
    BYTE pic_blob[64];
    memset(pic_blob, 0, sizeof(pic_blob));
    /* First 8 bytes = API pointer slot (will be overwritten by loader) */
    /* Bytes 8+: "code" */
    pic_blob[8] = 0xC3;  /* ret */

    PVOID entry = loader_load_pic(pic_blob, sizeof(pic_blob), api, &mod);

    int ok = 1;
    if (!entry) { ok = 0; }
    if (ok && mod.memory_base == NULL) { ok = 0; }
    if (ok && mod.entry_point != (BYTE *)mod.memory_base + 8) { ok = 0; }
    if (ok && mod.module_type != MODULE_TYPE_PIC) { ok = 0; }
    if (ok && mod.status != MODULE_STATUS_LOADING) { ok = 0; }

    /* Verify API pointer was injected at offset 0 */
    if (ok) {
        QWORD injected = *(QWORD *)mod.memory_base;
        if (injected != (QWORD)(ULONG_PTR)api) { ok = 0; }
    }

    if (ok) PASS();
    else FAIL("PIC load failed");

    mock_cleanup();
}

static void test_pic_loader_null_args(void) {
    MODULE_BUS_API *api = create_mock_api();
    LOADED_MODULE mod;
    memset(&mod, 0, sizeof(mod));

    TEST("PIC loader rejects NULL blob");
    if (loader_load_pic(NULL, 64, api, &mod) == NULL)
        PASS();
    else
        FAIL("NULL blob accepted");

    TEST("PIC loader rejects zero length");
    BYTE buf[64] = {0};
    if (loader_load_pic(buf, 0, api, &mod) == NULL)
        PASS();
    else
        FAIL("zero length accepted");

    TEST("PIC loader rejects too-small blob");
    if (loader_load_pic(buf, 8, api, &mod) == NULL)
        PASS();
    else
        FAIL("too-small blob accepted");

    mock_cleanup();
}

/* ================================================================== */
/*  Test: COFF loader — basic                                          */
/* ================================================================== */

static void test_coff_loader_basic(void) {
    TEST("COFF loader basic load");

    MODULE_BUS_API *api = create_mock_api();
    LOADED_MODULE mod;
    memset(&mod, 0, sizeof(mod));

    COFF_BLOB coff = build_minimal_coff();
    if (!coff.data) {
        FAIL("failed to build test COFF");
        return;
    }

    PVOID entry = loader_load_coff(coff.data, coff.size, api, &mod);

    int ok = 1;
    if (!entry) { ok = 0; }
    if (ok && mod.memory_base == NULL) { ok = 0; }
    if (ok && mod.entry_point == NULL) { ok = 0; }
    if (ok && mod.module_type != MODULE_TYPE_COFF) { ok = 0; }
    if (ok && mod.status != MODULE_STATUS_LOADING) { ok = 0; }

    /* Entry should point inside allocated memory */
    if (ok) {
        BYTE *base = (BYTE *)mod.memory_base;
        BYTE *ep = (BYTE *)mod.entry_point;
        if (ep < base || ep >= base + mod.memory_size) { ok = 0; }
    }

    /* Verify the code at entry matches what we put in (offset 4: mov rax,rcx; ret) */
    if (ok) {
        BYTE *ep = (BYTE *)mod.entry_point;
        if (ep[0] != 0x48 || ep[1] != 0x89 || ep[2] != 0xC8 || ep[3] != 0xC3) {
            ok = 0;
        }
    }

    if (ok) PASS();
    else FAIL("COFF basic load failed");

    free(coff.data);
    mock_cleanup();
}

static void test_coff_loader_null_args(void) {
    MODULE_BUS_API *api = create_mock_api();
    LOADED_MODULE mod;
    memset(&mod, 0, sizeof(mod));

    TEST("COFF loader rejects NULL data");
    if (loader_load_coff(NULL, 100, api, &mod) == NULL)
        PASS();
    else
        FAIL("NULL data accepted");

    TEST("COFF loader rejects zero length");
    BYTE buf[4] = {0};
    if (loader_load_coff(buf, 0, api, &mod) == NULL)
        PASS();
    else
        FAIL("zero length accepted");

    TEST("COFF loader rejects wrong machine");
    COFF_BLOB coff = build_minimal_coff();
    if (coff.data) {
        /* Corrupt machine type */
        COFF_FILE_HEADER *fh = (COFF_FILE_HEADER *)coff.data;
        fh->Machine = 0x014C;  /* i386 instead of AMD64 */
        if (loader_load_coff(coff.data, coff.size, api, &mod) == NULL)
            PASS();
        else
            FAIL("wrong machine accepted");
        free(coff.data);
    } else {
        FAIL("failed to build test COFF");
    }

    mock_cleanup();
}

/* ================================================================== */
/*  Test: COFF loader — relocations                                    */
/* ================================================================== */

static void test_coff_loader_relocations(void) {
    TEST("COFF loader processes REL32 relocation");

    MODULE_BUS_API *api = create_mock_api();
    LOADED_MODULE mod;
    memset(&mod, 0, sizeof(mod));

    COFF_BLOB coff = build_coff_with_relocs();
    if (!coff.data) {
        FAIL("failed to build test COFF");
        return;
    }

    PVOID entry = loader_load_coff(coff.data, coff.size, api, &mod);

    int ok = 1;
    if (!entry) { ok = 0; }

    if (ok) {
        /* The REL32 at offset 1 should have been patched.
         * It should contain a delta to the data section. */
        BYTE *text_base = (BYTE *)mod.memory_base;
        LONG rel32_val;
        memcpy(&rel32_val, text_base + 1, sizeof(LONG));

        /* REL32 = target - (fixup + 4)
         * target = data section base (at some offset after text)
         * fixup = text_base + 1
         * So: rel32_val should = data_base - (text_base + 1 + 4) */

        /* Data section starts after text (16 bytes aligned to 16 = 16 + 16 = 32) */
        BYTE *data_base = text_base + 32;  /* text rounded to 16 = 32 */
        LONG expected = (LONG)(data_base - (text_base + 1 + 4));

        if (rel32_val != expected) {
            printf("(rel32: got %ld, expected %ld) ", rel32_val, expected);
            ok = 0;
        }
    }

    if (ok) PASS();
    else FAIL("REL32 relocation incorrect");

    /* Now test ADDR64 */
    tests_run++;
    printf("  [TEST] %-55s ", "COFF loader processes ADDR64 relocation");

    if (entry) {
        BYTE *text_base = (BYTE *)mod.memory_base;
        QWORD addr64_val;
        memcpy(&addr64_val, text_base + 18, sizeof(QWORD));

        /* ADDR64 should contain absolute address of data section */
        BYTE *data_base = text_base + 32;
        QWORD expected = (QWORD)(ULONG_PTR)data_base;

        if (addr64_val == expected) {
            tests_passed++;
            printf("[PASS]\n");
        } else {
            tests_failed++;
            printf("[FAIL] addr64: got %llx, expected %llx\n",
                   (unsigned long long)addr64_val,
                   (unsigned long long)expected);
        }
    } else {
        tests_failed++;
        printf("[FAIL] no entry point\n");
    }

    free(coff.data);
    mock_cleanup();
}

/* ================================================================== */
/*  Test: COFF loader — no "go" symbol = fail                          */
/* ================================================================== */

static void test_coff_loader_no_entry(void) {
    TEST("COFF loader fails without 'go' symbol");

    MODULE_BUS_API *api = create_mock_api();
    LOADED_MODULE mod;
    memset(&mod, 0, sizeof(mod));

    COFF_BLOB coff = build_minimal_coff();
    if (!coff.data) {
        FAIL("failed to build test COFF");
        return;
    }

    /* Rename "go" symbol to "xx" */
    COFF_FILE_HEADER *fh = (COFF_FILE_HEADER *)coff.data;
    COFF_SYMBOL *sym = (COFF_SYMBOL *)(coff.data + fh->PointerToSymbolTable);
    memcpy(sym->Name.ShortName, "xx\0\0\0\0\0\0", 8);

    if (loader_load_coff(coff.data, coff.size, api, &mod) == NULL)
        PASS();
    else
        FAIL("missing 'go' symbol was accepted");

    free(coff.data);
    mock_cleanup();
}

/* ================================================================== */
/*  Test: COFF loader — _go alternate entry name                       */
/* ================================================================== */

static void test_coff_loader_underscore_go(void) {
    TEST("COFF loader accepts '_go' entry symbol");

    MODULE_BUS_API *api = create_mock_api();
    LOADED_MODULE mod;
    memset(&mod, 0, sizeof(mod));

    COFF_BLOB coff = build_minimal_coff();
    if (!coff.data) {
        FAIL("failed to build test COFF");
        return;
    }

    /* Rename "go" to "_go" */
    COFF_FILE_HEADER *fh = (COFF_FILE_HEADER *)coff.data;
    COFF_SYMBOL *sym = (COFF_SYMBOL *)(coff.data + fh->PointerToSymbolTable);
    memcpy(sym->Name.ShortName, "_go\0\0\0\0\0", 8);

    PVOID entry = loader_load_coff(coff.data, coff.size, api, &mod);
    if (entry && mod.entry_point != NULL)
        PASS();
    else
        FAIL("_go entry not found");

    free(coff.data);
    mock_cleanup();
}

/* ================================================================== */
/*  Test: Ed25519 verify package                                       */
/* ================================================================== */

static void test_verify_package_null(void) {
    BYTE key[32] = {0};

    TEST("verify_package rejects NULL");
    if (!loader_verify_package(NULL, 100, key))
        PASS();
    else
        FAIL("NULL accepted");

    TEST("verify_package rejects NULL key");
    BYTE buf[256];
    memset(buf, 0, sizeof(buf));
    build_package_header(buf, MODULE_TYPE_PIC, 64);
    if (!loader_verify_package(buf, sizeof(MODULE_PACKAGE_HDR) + 64, NULL))
        PASS();
    else
        FAIL("NULL key accepted");
}

static void test_verify_package_bad_header(void) {
    BYTE key[32] = {0};
    BYTE buf[4] = {0};

    TEST("verify_package rejects bad header");
    if (!loader_verify_package(buf, 4, key))
        PASS();
    else
        FAIL("bad header accepted");
}

/* ================================================================== */
/*  Test: decrypt_package null args                                    */
/* ================================================================== */

static void test_decrypt_package_null(void) {
    BYTE key[32] = {0};
    BYTE out[256];
    DWORD out_len = sizeof(out);

    TEST("decrypt_package rejects NULL package");
    if (!loader_decrypt_package(NULL, 100, key, out, &out_len))
        PASS();
    else
        FAIL("NULL package accepted");

    TEST("decrypt_package rejects NULL key");
    BYTE buf[256];
    memset(buf, 0, sizeof(buf));
    build_package_header(buf, MODULE_TYPE_PIC, 64);
    out_len = sizeof(out);
    if (!loader_decrypt_package(buf, sizeof(MODULE_PACKAGE_HDR) + 64,
                                NULL, out, &out_len))
        PASS();
    else
        FAIL("NULL key accepted");
}

/* ================================================================== */
/*  Test: COFF section too many sections                               */
/* ================================================================== */

static void test_coff_too_many_sections(void) {
    TEST("COFF loader rejects >32 sections");

    MODULE_BUS_API *api = create_mock_api();
    LOADED_MODULE mod;
    memset(&mod, 0, sizeof(mod));

    /* Build a COFF with too many sections */
    BYTE buf[64];
    memset(buf, 0, sizeof(buf));
    COFF_FILE_HEADER *fh = (COFF_FILE_HEADER *)buf;
    fh->Machine = IMAGE_FILE_MACHINE_AMD64;
    fh->NumberOfSections = 33;  /* > COFF_MAX_SECTIONS */

    if (loader_load_coff(buf, sizeof(buf), api, &mod) == NULL)
        PASS();
    else
        FAIL("too many sections accepted");

    mock_cleanup();
}

/* ================================================================== */
/*  Test: COFF loader zero sections                                    */
/* ================================================================== */

static void test_coff_zero_sections(void) {
    TEST("COFF loader rejects zero sections");

    MODULE_BUS_API *api = create_mock_api();
    LOADED_MODULE mod;
    memset(&mod, 0, sizeof(mod));

    BYTE buf[64];
    memset(buf, 0, sizeof(buf));
    COFF_FILE_HEADER *fh = (COFF_FILE_HEADER *)buf;
    fh->Machine = IMAGE_FILE_MACHINE_AMD64;
    fh->NumberOfSections = 0;

    if (loader_load_coff(buf, sizeof(buf), api, &mod) == NULL)
        PASS();
    else
        FAIL("zero sections accepted");

    mock_cleanup();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void) {
    printf("\n=== SPECTER Module Loader Test Suite ===\n\n");

    printf("[Package Header Tests]\n");
    test_parse_header_valid();
    test_parse_header_coff();
    test_parse_header_bad_magic();
    test_parse_header_bad_version();
    test_parse_header_bad_type();
    test_parse_header_truncated();
    test_parse_header_null();
    test_parse_header_too_small();
    test_parse_header_zero_size();

    printf("\n[PIC Loader Tests]\n");
    test_pic_loader_basic();
    test_pic_loader_null_args();

    printf("\n[COFF Loader Tests]\n");
    test_coff_loader_basic();
    test_coff_loader_null_args();
    test_coff_loader_relocations();
    test_coff_loader_no_entry();
    test_coff_loader_underscore_go();
    test_coff_too_many_sections();
    test_coff_zero_sections();

    printf("\n[Signature Verification Tests]\n");
    test_verify_package_null();
    test_verify_package_bad_header();

    printf("\n[Decryption Tests]\n");
    test_decrypt_package_null();

    printf("\n=== Results: %d/%d passed, %d failed ===\n\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
