/**
 * SPECTER Implant — Cached Heap Allocator
 *
 * Resolves GetProcessHeap/HeapAlloc/HeapFree once via PEB walk,
 * caches the handle + function pointers for all subsequent allocations.
 * Avoids repeated PEB walks on every alloc/free call.
 */

#ifndef HEAP_H
#define HEAP_H

#include "specter.h"

/**
 * Initialize the cached heap handle.
 * Must be called after PEB is available (during comms_init or later).
 * Safe to call multiple times — returns TRUE immediately if already cached.
 */
BOOL init_heap_cache(void);

/**
 * Allocate zeroed memory from the cached process heap.
 * Initializes the cache on first call if not already done.
 * Returns NULL on failure.
 */
PVOID heap_alloc_cached(DWORD size);

/**
 * Free memory previously allocated with heap_alloc_cached.
 * No-op if ptr is NULL or heap cache is not initialized.
 */
void heap_free_cached(PVOID ptr);

#endif /* HEAP_H */
