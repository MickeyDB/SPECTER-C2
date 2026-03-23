/**
 * SPECTER Module Template
 *
 * Reference implementation showing standard module structure:
 * argument parsing, subcommand dispatch, bus API usage, and
 * error handling.  Copy this file as a starting point for new modules.
 *
 * Build: make modules  (produces build/modules/template.bin)
 */

#include "module.h"

/* ------------------------------------------------------------------ */
/*  Subcommand handlers                                                */
/* ------------------------------------------------------------------ */

static DWORD cmd_hello(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    const char *name;

    /* Expect arg[1] = name string */
    name = module_arg_string(args, 1);
    if (!name) {
        MODULE_OUTPUT_ERROR(api, "hello: missing name argument");
        return MODULE_ERR_ARGS;
    }

    /* Build output using bus API */
    MODULE_OUTPUT_TEXT(api, "Hello from SPECTER module: ");
    MODULE_OUTPUT_TEXT(api, name);

    return MODULE_SUCCESS;
}

static DWORD cmd_ping(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    MODULE_OUTPUT_TEXT(api, "pong");
    return MODULE_SUCCESS;
}

static DWORD cmd_resolve_demo(MODULE_BUS_API *api, const MODULE_ARGS *args)
{
    PVOID func;

    /* Demonstrate API resolution via the bus */
    func = api->resolve("kernel32.dll", "GetTickCount");
    if (!func) {
        MODULE_OUTPUT_ERROR(api, "resolve_demo: failed to resolve GetTickCount");
        return MODULE_ERR_RESOLVE;
    }

    MODULE_OUTPUT_TEXT(api, "resolve_demo: successfully resolved GetTickCount");
    return MODULE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Module entry point                                                 */
/* ------------------------------------------------------------------ */

/**
 * Standard module entry.  First argument is always the subcommand string.
 *
 * @param api       Bus API function table
 * @param args_raw  Raw argument blob
 * @param args_len  Length of argument blob
 * @return          MODULE_SUCCESS or MODULE_ERR_* code
 */
DWORD module_entry(MODULE_BUS_API *api, BYTE *args_raw, DWORD args_len)
{
    MODULE_ARGS  args;
    const char  *subcmd;

    /* Parse argument blob */
    if (!module_parse_args(args_raw, args_len, &args)) {
        MODULE_OUTPUT_ERROR(api, "template: failed to parse arguments");
        return MODULE_ERR_ARGS;
    }

    /* First argument is the subcommand */
    subcmd = module_arg_string(&args, 0);
    if (!subcmd) {
        MODULE_OUTPUT_ERROR(api, "template: missing subcommand");
        return MODULE_ERR_ARGS;
    }

    /* Dispatch subcommand */
    if (spec_strcmp(subcmd, "hello") == 0)
        return cmd_hello(api, &args);

    if (spec_strcmp(subcmd, "ping") == 0)
        return cmd_ping(api, &args);

    if (spec_strcmp(subcmd, "resolve") == 0)
        return cmd_resolve_demo(api, &args);

    /* Unknown subcommand */
    MODULE_OUTPUT_ERROR(api, "template: unknown subcommand");
    return MODULE_ERR_UNSUPPORTED;
}
