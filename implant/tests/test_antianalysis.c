/**
 * SPECTER Implant — Anti-Analysis Test Suite
 *
 * Tests VM detection (CPUID), debugger detection (PEB flag, RDTSC,
 * hardware breakpoints), sandbox detection (process count, timing),
 * response actions, and configuration defaults.
 *
 * Build (native, not PIC):
 *   gcc -o test_antianalysis test_antianalysis.c \
 *       ../core/src/evasion/antianalysis.c \
 *       ../core/src/string.c ../core/src/hash.c \
 *       -I../core/include -DTEST_BUILD
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Include project headers directly — they provide all needed types */
#include "specter.h"
#include "ntdefs.h"
#include "antianalysis.h"

/* Global context required by antianalysis.c */
IMPLANT_CONTEXT g_ctx;

/* Stub function implementations for test builds */
PPEB get_peb(void) { return NULL; }
PVOID find_module_by_hash(DWORD hash) { (void)hash; return NULL; }
PVOID find_export_by_hash(PVOID base, DWORD hash) { (void)base; (void)hash; return NULL; }
PVOID resolve_function(DWORD mh, DWORD fh) { (void)mh; (void)fh; return NULL; }

/* ------------------------------------------------------------------ */
/*  Test framework                                                     */
/* ------------------------------------------------------------------ */

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ(a, b, msg) do { \
    tests_run++; \
    if ((a) == (b)) { tests_passed++; printf("  PASS: %s\n", msg); } \
    else { tests_failed++; printf("  FAIL: %s (got %d, expected %d)\n", msg, (int)(a), (int)(b)); } \
} while(0)

#define ASSERT_NE(a, b, msg) do { \
    tests_run++; \
    if ((a) != (b)) { tests_passed++; printf("  PASS: %s\n", msg); } \
    else { tests_failed++; printf("  FAIL: %s (both equal %d)\n", msg, (int)(a)); } \
} while(0)

#define ASSERT_TRUE(cond, msg) ASSERT_EQ(!!(cond), 1, msg)
#define ASSERT_FALSE(cond, msg) ASSERT_EQ(!!(cond), 0, msg)

#define ASSERT_GE(a, b, msg) do { \
    tests_run++; \
    if ((a) >= (b)) { tests_passed++; printf("  PASS: %s\n", msg); } \
    else { tests_failed++; printf("  FAIL: %s (got %d, expected >= %d)\n", msg, (int)(a), (int)(b)); } \
} while(0)

/* ------------------------------------------------------------------ */
/*  Test: default configuration                                        */
/* ------------------------------------------------------------------ */

static void test_default_config(void) {
    printf("\n--- Default Config Tests ---\n");

    ANTIANALYSIS_CONFIG cfg;
    memset(&cfg, 0xFF, sizeof(cfg));
    antianalysis_default_config(&cfg);

    ASSERT_EQ(cfg.response, AA_RESPONSE_EXIT, "default response is EXIT");
    ASSERT_EQ(cfg.vm_threshold, 50, "default VM threshold is 50");
    ASSERT_EQ(cfg.sb_threshold, 50, "default sandbox threshold is 50");
    ASSERT_EQ(cfg.dbg_threshold, 50, "default debugger threshold is 50");
    ASSERT_TRUE(cfg.check_vm, "VM check enabled by default");
    ASSERT_TRUE(cfg.check_sandbox, "sandbox check enabled by default");
    ASSERT_TRUE(cfg.check_debugger, "debugger check enabled by default");
}

/* ------------------------------------------------------------------ */
/*  Test: clean environment (no detection)                             */
/* ------------------------------------------------------------------ */

static void test_clean_environment(void) {
    printf("\n--- Clean Environment Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_peb_debugged(0);
    aa_test_set_rdtsc_delta(100);
    aa_test_set_process_count(100);
    aa_test_set_debug_registers(0, 0, 0, 0);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_CLEAN, "clean env returns ANALYSIS_CLEAN");
    ASSERT_EQ(result.confidence, 0, "clean env has zero confidence");
    ASSERT_EQ(result.indicator_count, 0, "clean env has no indicators");
}

/* ------------------------------------------------------------------ */
/*  Test: VM detection via CPUID                                       */
/* ------------------------------------------------------------------ */

static void test_vm_cpuid_vmware(void) {
    printf("\n--- VM CPUID (VMware) Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_debugger = FALSE;
    cfg.check_sandbox = FALSE;
    cfg.vm_threshold = 30;

    DWORD ebx, ecx, edx;
    memcpy(&ebx, "VMwa", 4);
    memcpy(&ecx, "reVM", 4);
    memcpy(&edx, "ware", 4);
    aa_test_set_cpuid_result(CPUID_HYPERVISOR_BIT, ebx, ecx, edx);
    aa_test_set_peb_debugged(0);
    aa_test_set_rdtsc_delta(100);
    aa_test_set_process_count(100);
    aa_test_set_debug_registers(0, 0, 0, 0);
    aa_test_set_mac_prefix(0);
    aa_test_set_smbios_vm(FALSE);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_VM, "VMware CPUID detected as VM");
    ASSERT_GE(result.confidence, 30, "VMware confidence >= 30");
    ASSERT_TRUE(result.indicator_count > 0, "has indicators");

    BOOL found = FALSE;
    for (DWORD i = 0; i < result.indicator_count; i++) {
        if (result.indicators[i] == AA_IND_CPUID_HYPERVISOR)
            found = TRUE;
    }
    ASSERT_TRUE(found, "CPUID hypervisor indicator present");
}

static void test_vm_cpuid_hyperv(void) {
    printf("\n--- VM CPUID (Hyper-V) Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_debugger = FALSE;
    cfg.check_sandbox = FALSE;
    cfg.vm_threshold = 30;

    DWORD ebx, ecx, edx;
    memcpy(&ebx, "Micr", 4);
    memcpy(&ecx, "osof", 4);
    memcpy(&edx, "t Hv", 4);
    aa_test_set_cpuid_result(CPUID_HYPERVISOR_BIT, ebx, ecx, edx);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_VM, "Hyper-V CPUID detected as VM");
    ASSERT_GE(result.confidence, 30, "Hyper-V confidence >= 30");
}

static void test_vm_cpuid_kvm(void) {
    printf("\n--- VM CPUID (KVM) Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_debugger = FALSE;
    cfg.check_sandbox = FALSE;
    cfg.vm_threshold = 30;

    DWORD ebx, ecx, edx;
    memcpy(&ebx, "KVMK", 4);
    memcpy(&ecx, "VMKV", 4);
    memcpy(&edx, "M\0\0\0", 4);
    aa_test_set_cpuid_result(CPUID_HYPERVISOR_BIT, ebx, ecx, edx);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_VM, "KVM CPUID detected as VM");
}

static void test_vm_no_hypervisor_bit(void) {
    printf("\n--- VM No Hypervisor Bit ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_debugger = FALSE;
    cfg.check_sandbox = FALSE;

    aa_test_set_cpuid_result(0, 0, 0, 0);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_CLEAN, "no hypervisor bit = clean");
}

/* ------------------------------------------------------------------ */
/*  Test: debugger detection via PEB                                   */
/* ------------------------------------------------------------------ */

static void test_debugger_peb(void) {
    printf("\n--- Debugger PEB Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_vm = FALSE;
    cfg.check_sandbox = FALSE;
    cfg.dbg_threshold = 40;

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_peb_debugged(1);
    aa_test_set_rdtsc_delta(100);
    aa_test_set_process_count(100);
    aa_test_set_debug_registers(0, 0, 0, 0);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_DEBUGGER, "PEB debugged flag detected");
    ASSERT_GE(result.confidence, 50, "PEB debugged confidence >= 50");

    BOOL found = FALSE;
    for (DWORD i = 0; i < result.indicator_count; i++) {
        if (result.indicators[i] == AA_IND_PEB_DEBUGGED)
            found = TRUE;
    }
    ASSERT_TRUE(found, "PEB debugged indicator present");
}

/* ------------------------------------------------------------------ */
/*  Test: debugger detection via hardware breakpoints                  */
/* ------------------------------------------------------------------ */

static void test_debugger_hw_breakpoints(void) {
    printf("\n--- Debugger HW Breakpoints Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_vm = FALSE;
    cfg.check_sandbox = FALSE;
    cfg.dbg_threshold = 30;

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_peb_debugged(0);
    aa_test_set_rdtsc_delta(100);
    aa_test_set_process_count(100);
    aa_test_set_debug_registers(0x7FFE0000, 0, 0, 0);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_DEBUGGER, "HW breakpoints detected");
    ASSERT_GE(result.confidence, 35, "HW bp confidence >= 35");

    BOOL found = FALSE;
    for (DWORD i = 0; i < result.indicator_count; i++) {
        if (result.indicators[i] == AA_IND_HW_BREAKPOINTS)
            found = TRUE;
    }
    ASSERT_TRUE(found, "HW breakpoints indicator present");
}

/* ------------------------------------------------------------------ */
/*  Test: debugger detection via RDTSC timing                          */
/* ------------------------------------------------------------------ */

static void test_debugger_rdtsc(void) {
    printf("\n--- Debugger RDTSC Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_vm = FALSE;
    cfg.check_sandbox = FALSE;
    cfg.dbg_threshold = 25;

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_peb_debugged(0);
    aa_test_set_rdtsc_delta(50000000);
    aa_test_set_process_count(100);
    aa_test_set_debug_registers(0, 0, 0, 0);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_DEBUGGER, "RDTSC anomaly detected");
    ASSERT_GE(result.confidence, 30, "RDTSC confidence >= 30");
}

/* ------------------------------------------------------------------ */
/*  Test: sandbox detection via low process count                      */
/* ------------------------------------------------------------------ */

static void test_sandbox_low_procs(void) {
    printf("\n--- Sandbox Low Process Count Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_vm = FALSE;
    cfg.check_debugger = FALSE;
    cfg.sb_threshold = 25;

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_peb_debugged(0);
    aa_test_set_rdtsc_delta(100);
    aa_test_set_process_count(10);
    aa_test_set_debug_registers(0, 0, 0, 0);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_SANDBOX, "low proc count = sandbox");
    ASSERT_GE(result.confidence, 30, "low proc confidence >= 30");

    BOOL found = FALSE;
    for (DWORD i = 0; i < result.indicator_count; i++) {
        if (result.indicators[i] == AA_IND_LOW_PROC_COUNT)
            found = TRUE;
    }
    ASSERT_TRUE(found, "low proc count indicator present");
}

/* ------------------------------------------------------------------ */
/*  Test: sandbox timing acceleration                                  */
/* ------------------------------------------------------------------ */

static void test_sandbox_timing(void) {
    printf("\n--- Sandbox Timing Acceleration Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_vm = FALSE;
    cfg.check_debugger = FALSE;
    cfg.sb_threshold = 20;

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_peb_debugged(0);
    aa_test_set_rdtsc_delta(20000000);
    aa_test_set_process_count(100);
    aa_test_set_debug_registers(0, 0, 0, 0);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_SANDBOX, "timing accel = sandbox");
    ASSERT_GE(result.confidence, 25, "timing confidence >= 25");
}

/* ------------------------------------------------------------------ */
/*  Test: threshold gating                                             */
/* ------------------------------------------------------------------ */

static void test_threshold_gating(void) {
    printf("\n--- Threshold Gating Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_vm = FALSE;
    cfg.check_sandbox = FALSE;
    cfg.dbg_threshold = 90;

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_peb_debugged(1);
    aa_test_set_rdtsc_delta(100);
    aa_test_set_process_count(100);
    aa_test_set_debug_registers(0, 0, 0, 0);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_CLEAN, "below threshold = clean");
}

/* ------------------------------------------------------------------ */
/*  Test: disabled checks                                              */
/* ------------------------------------------------------------------ */

static void test_disabled_checks(void) {
    printf("\n--- Disabled Checks Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_vm = FALSE;
    cfg.check_sandbox = FALSE;
    cfg.check_debugger = FALSE;

    aa_test_set_cpuid_result(CPUID_HYPERVISOR_BIT, 0, 0, 0);
    aa_test_set_peb_debugged(1);
    aa_test_set_rdtsc_delta(50000000);
    aa_test_set_process_count(5);
    aa_test_set_debug_registers(0x1000, 0, 0, 0);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_CLEAN, "all checks disabled = clean");
}

/* ------------------------------------------------------------------ */
/*  Test: response actions                                             */
/* ------------------------------------------------------------------ */

static void test_response_exit(void) {
    printf("\n--- Response EXIT Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.running = TRUE;

    antianalysis_respond(&ctx, AA_RESPONSE_EXIT);

    ASSERT_FALSE(ctx.running, "EXIT zeroes running flag");
}

static void test_response_sleep_forever(void) {
    printf("\n--- Response SLEEP_FOREVER Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.running = TRUE;

    antianalysis_respond(&ctx, AA_RESPONSE_SLEEP_FOREVER);

    ASSERT_FALSE(ctx.running, "SLEEP_FOREVER sets running=FALSE in test");
}

static void test_response_decoy(void) {
    printf("\n--- Response DECOY Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.running = TRUE;

    antianalysis_respond(&ctx, AA_RESPONSE_DECOY);

    ASSERT_FALSE(ctx.running, "DECOY zeroes running flag");
}

static void test_response_ignore(void) {
    printf("\n--- Response IGNORE Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.running = TRUE;

    antianalysis_respond(&ctx, AA_RESPONSE_IGNORE);

    ASSERT_TRUE(ctx.running, "IGNORE keeps running = TRUE");
}

/* ------------------------------------------------------------------ */
/*  Test: NULL parameter handling                                      */
/* ------------------------------------------------------------------ */

static void test_null_params(void) {
    printf("\n--- NULL Parameter Tests ---\n");

    ANALYSIS_RESULT result;
    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);

    ANALYSIS_TYPE type;
    type = antianalysis_check(NULL, &cfg, &result);
    ASSERT_EQ(type, ANALYSIS_CLEAN, "NULL ctx returns clean");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    type = antianalysis_check(&ctx, NULL, &result);
    ASSERT_EQ(type, ANALYSIS_CLEAN, "NULL cfg returns clean");

    type = antianalysis_check(&ctx, &cfg, NULL);
    ASSERT_EQ(type, ANALYSIS_CLEAN, "NULL result returns clean");

    antianalysis_default_config(NULL);
    ASSERT_TRUE(1, "NULL default_config does not crash");
}

/* ------------------------------------------------------------------ */
/*  Test: detection priority (debugger > VM > sandbox)                 */
/* ------------------------------------------------------------------ */

static void test_detection_priority(void) {
    printf("\n--- Detection Priority Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.dbg_threshold = 40;
    cfg.vm_threshold = 30;
    cfg.sb_threshold = 20;

    DWORD ebx, ecx, edx;
    memcpy(&ebx, "VMwa", 4);
    memcpy(&ecx, "reVM", 4);
    memcpy(&edx, "ware", 4);
    aa_test_set_cpuid_result(CPUID_HYPERVISOR_BIT, ebx, ecx, edx);
    aa_test_set_peb_debugged(1);
    aa_test_set_rdtsc_delta(100);
    aa_test_set_process_count(10);
    aa_test_set_debug_registers(0, 0, 0, 0);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_DEBUGGER, "debugger detected before VM");
}

/* ------------------------------------------------------------------ */
/*  Test: VM detection via MAC address prefix                          */
/* ------------------------------------------------------------------ */

static void test_vm_mac_vmware(void) {
    printf("\n--- VM MAC Prefix (VMware) Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_debugger = FALSE;
    cfg.check_sandbox = FALSE;
    cfg.vm_threshold = 25;

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_mac_prefix(0x000C29);  /* VMware OUI */
    aa_test_set_smbios_vm(FALSE);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_VM, "VMware MAC detected as VM");
    ASSERT_GE(result.confidence, 30, "VMware MAC confidence >= 30");

    BOOL found = FALSE;
    for (DWORD i = 0; i < result.indicator_count; i++) {
        if (result.indicators[i] == AA_IND_VM_MAC_PREFIX)
            found = TRUE;
    }
    ASSERT_TRUE(found, "MAC prefix indicator present");

    /* Clean up */
    aa_test_set_mac_prefix(0);
}

static void test_vm_mac_vbox(void) {
    printf("\n--- VM MAC Prefix (VirtualBox) Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_debugger = FALSE;
    cfg.check_sandbox = FALSE;
    cfg.vm_threshold = 25;

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_mac_prefix(0x080027);  /* VirtualBox OUI */
    aa_test_set_smbios_vm(FALSE);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_VM, "VBox MAC detected as VM");

    aa_test_set_mac_prefix(0);
}

static void test_vm_mac_clean(void) {
    printf("\n--- VM MAC Prefix (Clean) Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_mac_prefix(0);
    aa_test_set_smbios_vm(FALSE);

    ANALYSIS_RESULT result;
    memset(&result, 0, sizeof(result));
    DWORD conf = antianalysis_check_vm(&ctx, &result);

    ASSERT_EQ(conf, 0, "clean MAC = zero VM confidence");
}

/* ------------------------------------------------------------------ */
/*  Test: VM detection via SMBIOS firmware                             */
/* ------------------------------------------------------------------ */

static void test_vm_smbios(void) {
    printf("\n--- VM SMBIOS Firmware Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_debugger = FALSE;
    cfg.check_sandbox = FALSE;
    cfg.vm_threshold = 30;

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_mac_prefix(0);
    aa_test_set_smbios_vm(TRUE);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_VM, "SMBIOS VM string detected");
    ASSERT_GE(result.confidence, 35, "SMBIOS confidence >= 35");

    BOOL found = FALSE;
    for (DWORD i = 0; i < result.indicator_count; i++) {
        if (result.indicators[i] == AA_IND_SMBIOS_FIRMWARE)
            found = TRUE;
    }
    ASSERT_TRUE(found, "SMBIOS firmware indicator present");

    aa_test_set_smbios_vm(FALSE);
}

/* ------------------------------------------------------------------ */
/*  Test: sandbox detection via empty recent documents                 */
/* ------------------------------------------------------------------ */

static void test_sandbox_empty_recent_docs(void) {
    printf("\n--- Sandbox Empty Recent Docs Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    ANTIANALYSIS_CONFIG cfg;
    antianalysis_default_config(&cfg);
    cfg.check_vm = FALSE;
    cfg.check_debugger = FALSE;
    cfg.sb_threshold = 10;

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_peb_debugged(0);
    aa_test_set_rdtsc_delta(100);
    aa_test_set_process_count(100);
    aa_test_set_debug_registers(0, 0, 0, 0);
    aa_test_set_recent_docs_count(0);

    ANALYSIS_RESULT result;
    ANALYSIS_TYPE type = antianalysis_check(&ctx, &cfg, &result);

    ASSERT_EQ(type, ANALYSIS_SANDBOX, "empty recent docs = sandbox");
    ASSERT_GE(result.confidence, 15, "recent docs confidence >= 15");

    BOOL found = FALSE;
    for (DWORD i = 0; i < result.indicator_count; i++) {
        if (result.indicators[i] == AA_IND_EMPTY_RECENT_DOCS)
            found = TRUE;
    }
    ASSERT_TRUE(found, "empty recent docs indicator present");

    aa_test_set_recent_docs_count(10);  /* Reset */
}

static void test_sandbox_has_recent_docs(void) {
    printf("\n--- Sandbox Has Recent Docs Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    aa_test_set_rdtsc_delta(100);
    aa_test_set_process_count(100);
    aa_test_set_recent_docs_count(10);

    ANALYSIS_RESULT result;
    memset(&result, 0, sizeof(result));
    DWORD conf = antianalysis_check_sandbox(&ctx, &result);

    /* With 100 procs, normal timing, and recent docs, confidence = 0 */
    ASSERT_EQ(conf, 0, "has recent docs = no sandbox signal");
}

/* ------------------------------------------------------------------ */
/*  Test: combined VM signals stack (CPUID + MAC + SMBIOS)             */
/* ------------------------------------------------------------------ */

static void test_combined_vm(void) {
    printf("\n--- Combined VM Signal Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* Set both CPUID and MAC indicators */
    DWORD ebx, ecx, edx;
    memcpy(&ebx, "VMwa", 4);
    memcpy(&ecx, "reVM", 4);
    memcpy(&edx, "ware", 4);
    aa_test_set_cpuid_result(CPUID_HYPERVISOR_BIT, ebx, ecx, edx);
    aa_test_set_mac_prefix(0x000C29);
    aa_test_set_smbios_vm(TRUE);

    ANALYSIS_RESULT result;
    memset(&result, 0, sizeof(result));
    DWORD conf = antianalysis_check_vm(&ctx, &result);

    /* CPUID(40) + MAC(30) + SMBIOS(35) = capped at 100 */
    ASSERT_GE(conf, 100, "combined VM >= 100");
    ASSERT_TRUE(result.indicator_count >= 3, "at least 3 VM indicators");

    aa_test_set_cpuid_result(0, 0, 0, 0);
    aa_test_set_mac_prefix(0);
    aa_test_set_smbios_vm(FALSE);
}

/* ------------------------------------------------------------------ */
/*  Test: individual check functions                                   */
/* ------------------------------------------------------------------ */

static void test_individual_vm_check(void) {
    printf("\n--- Individual VM Check Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    DWORD ebx, ecx, edx;
    memcpy(&ebx, "VMwa", 4);
    memcpy(&ecx, "reVM", 4);
    memcpy(&edx, "ware", 4);
    aa_test_set_cpuid_result(CPUID_HYPERVISOR_BIT, ebx, ecx, edx);
    aa_test_set_mac_prefix(0);
    aa_test_set_smbios_vm(FALSE);

    ANALYSIS_RESULT result;
    memset(&result, 0, sizeof(result));
    DWORD conf = antianalysis_check_vm(&ctx, &result);

    ASSERT_GE(conf, 40, "VM check returns >= 40 for VMware");
    ASSERT_TRUE(result.indicator_count > 0, "VM check sets indicators");
}

static void test_individual_debugger_check(void) {
    printf("\n--- Individual Debugger Check Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    aa_test_set_peb_debugged(1);
    aa_test_set_rdtsc_delta(100);
    aa_test_set_debug_registers(0, 0, 0, 0);

    ANALYSIS_RESULT result;
    memset(&result, 0, sizeof(result));
    DWORD conf = antianalysis_check_debugger(&ctx, &result);

    ASSERT_GE(conf, 50, "debugger check >= 50 for PEB flag");
}

static void test_individual_sandbox_check(void) {
    printf("\n--- Individual Sandbox Check Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    aa_test_set_rdtsc_delta(100);
    aa_test_set_process_count(5);

    ANALYSIS_RESULT result;
    memset(&result, 0, sizeof(result));
    DWORD conf = antianalysis_check_sandbox(&ctx, &result);

    ASSERT_GE(conf, 30, "sandbox check >= 30 for low procs");
}

/* ------------------------------------------------------------------ */
/*  Test: combined debugger signals stack                              */
/* ------------------------------------------------------------------ */

static void test_combined_debugger(void) {
    printf("\n--- Combined Debugger Signal Tests ---\n");

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));

    aa_test_set_peb_debugged(1);
    aa_test_set_rdtsc_delta(50000000);
    aa_test_set_debug_registers(0x1000, 0x2000, 0, 0);

    ANALYSIS_RESULT result;
    memset(&result, 0, sizeof(result));
    DWORD conf = antianalysis_check_debugger(&ctx, &result);

    /* PEB(50) + RDTSC(30) + HW BP(35) = capped at 100 */
    ASSERT_GE(conf, 100, "combined debugger >= 100");
    ASSERT_TRUE(result.indicator_count >= 3, "at least 3 indicators");
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("=== SPECTER Anti-Analysis Test Suite ===\n");

    test_default_config();
    test_clean_environment();
    test_vm_cpuid_vmware();
    test_vm_cpuid_hyperv();
    test_vm_cpuid_kvm();
    test_vm_no_hypervisor_bit();
    test_debugger_peb();
    test_debugger_hw_breakpoints();
    test_debugger_rdtsc();
    test_sandbox_low_procs();
    test_sandbox_timing();
    test_threshold_gating();
    test_disabled_checks();
    test_response_exit();
    test_response_sleep_forever();
    test_response_decoy();
    test_response_ignore();
    test_null_params();
    test_detection_priority();
    test_vm_mac_vmware();
    test_vm_mac_vbox();
    test_vm_mac_clean();
    test_vm_smbios();
    test_sandbox_empty_recent_docs();
    test_sandbox_has_recent_docs();
    test_combined_vm();
    test_individual_vm_check();
    test_individual_debugger_check();
    test_individual_sandbox_check();
    test_combined_debugger();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
