/**
 * SPECTER Implant — PEB Walking & Module Resolution
 *
 * PEB-based module enumeration and PE export directory parsing
 * for runtime API resolution without static imports.
 */

#ifndef PEB_H
#define PEB_H

#include "specter.h"

/* ------------------------------------------------------------------ */
/*  PEB access                                                         */
/* ------------------------------------------------------------------ */

/**
 * Read the Process Environment Block pointer from TEB via GS:[0x60].
 */
PPEB get_peb(void);

/* ------------------------------------------------------------------ */
/*  Module resolution                                                  */
/* ------------------------------------------------------------------ */

/**
 * Walk PEB→Ldr→InLoadOrderModuleList, hash each DLL's BaseDllName,
 * and return the DllBase of the module whose hash matches.
 * Returns NULL if no module matches.
 */
PVOID find_module_by_hash(DWORD hash);

/* ------------------------------------------------------------------ */
/*  Export resolution                                                   */
/* ------------------------------------------------------------------ */

/**
 * Parse the PE export directory of a loaded module, hash each export
 * name, and return the function address whose hash matches.
 * Handles forwarded exports (recursively resolves through other DLLs).
 * Returns NULL if the export is not found.
 */
PVOID find_export_by_hash(PVOID module_base, DWORD hash);

/* ------------------------------------------------------------------ */
/*  Combined resolution                                                */
/* ------------------------------------------------------------------ */

/**
 * Resolve a function by module hash + export name hash.
 * Calls find_module_by_hash then find_export_by_hash.
 * Returns NULL on failure.
 */
PVOID resolve_function(DWORD module_hash, DWORD func_hash);

#endif /* PEB_H */
