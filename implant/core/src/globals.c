/**
 * SPECTER Implant — Global State
 *
 * Central implant context and syscall table instances.
 */

#include "specter.h"
#include "syscalls.h"

/* ------------------------------------------------------------------ */
/*  Global implant context                                              */
/* ------------------------------------------------------------------ */

IMPLANT_CONTEXT g_ctx;
