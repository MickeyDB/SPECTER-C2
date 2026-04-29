#include "module.h"

DWORD MODULE_ENTRYPOINT module_entry(MODULE_BUS_API *api, BYTE *args_raw, DWORD args_len)
{
    (void)api;
    (void)args_raw;
    (void)args_len;

    return MODULE_SUCCESS;
}
