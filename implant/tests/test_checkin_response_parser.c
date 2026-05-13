#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "specter.h"
#include "task.h"

#define TLV_VERSION     0x01
#define TLV_TASK_BLOCK  0x0200
#define TLV_TASK_ID     0x0201
#define TLV_TASK_TYPE   0x0202
#define TLV_TASK_ARGS   0x0203

void comms_test_parse_checkin_response(IMPLANT_CONTEXT *impl_ctx,
                                       const BYTE *data,
                                       DWORD len);

PVOID task_alloc(DWORD size) {
    return malloc(size);
}

void task_free(PVOID ptr) {
    free(ptr);
}

DWORD parse_task_type(const char *type_str, DWORD len) {
    const char module_load[] = "module_load";
    if (len == sizeof(module_load) - 1 &&
        memcmp(type_str, module_load, sizeof(module_load) - 1) == 0) {
        return TASK_TYPE_MODULE;
    }
    return 0;
}

PVOID find_module_by_hash(DWORD hash) {
    (void)hash;
    return NULL;
}

PVOID find_export_by_hash(PVOID module_base, DWORD hash) {
    (void)module_base;
    (void)hash;
    return NULL;
}

static void write_u16_le(BYTE *buf, DWORD *pos, WORD value) {
    buf[(*pos)++] = (BYTE)value;
    buf[(*pos)++] = (BYTE)(value >> 8);
}

static void write_u32_le(BYTE *buf, DWORD *pos, DWORD value) {
    buf[(*pos)++] = (BYTE)value;
    buf[(*pos)++] = (BYTE)(value >> 8);
    buf[(*pos)++] = (BYTE)(value >> 16);
    buf[(*pos)++] = (BYTE)(value >> 24);
}

static void write_tlv(BYTE *buf, DWORD *pos, WORD tag,
                      const BYTE *value, DWORD len) {
    write_u16_le(buf, pos, tag);
    write_u32_le(buf, pos, len);
    memcpy(buf + *pos, value, len);
    *pos += len;
}

static int check(int condition, const char *name) {
    if (condition) {
        printf("[PASS] %s\n", name);
        return 1;
    }

    printf("[FAIL] %s\n", name);
    return 0;
}

int main(void) {
    BYTE task_args[] = {
        'S','P','E','C',
        0x01,0x00,0x00,0x00,
        0x00,0x7f,0x80,0xff,
        0x00,
        0x02,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x06,0x00,0x00,0x00,
        's','t','a','r','t',0x00,
        0x01,0x00,0x00,0x00,
        0x04,0x00,0x00,0x00,
        0xfa,0x00,0x00,0x00
    };
    BYTE task_id[] = "task-parser-001";
    BYTE task_type[] = "module_load";
    BYTE task_block[256];
    BYTE response[512];
    DWORD block_len = 0;
    DWORD response_len = 0;
    int passed = 0;

    write_tlv(task_block, &block_len, TLV_TASK_ID, task_id, (DWORD)strlen((char *)task_id));
    write_tlv(task_block, &block_len, TLV_TASK_TYPE, task_type, (DWORD)strlen((char *)task_type));
    write_tlv(task_block, &block_len, TLV_TASK_ARGS, task_args, (DWORD)sizeof(task_args));

    response[response_len++] = TLV_VERSION;
    write_tlv(response, &response_len, TLV_TASK_BLOCK, task_block, block_len);

    IMPLANT_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    comms_test_parse_checkin_response(&ctx, response, response_len);

    passed += check(ctx.pending_task_count == 1, "one task queued");
    passed += check(ctx.pending_tasks[0].task_type == TASK_TYPE_MODULE, "module_load parsed as module task");
    passed += check(strcmp(ctx.pending_tasks[0].task_id, "task-parser-001") == 0, "task id preserved");
    passed += check(ctx.pending_tasks[0].data_len == sizeof(task_args), "binary argument length preserved");
    passed += check(ctx.pending_tasks[0].data != NULL, "binary argument buffer allocated");
    passed += check(ctx.pending_tasks[0].data &&
                    memcmp(ctx.pending_tasks[0].data, task_args, sizeof(task_args)) == 0,
                    "binary arguments preserved byte-for-byte");
    passed += check(ctx.pending_tasks[0].data &&
                    ctx.pending_tasks[0].data[sizeof(task_args)] == 0,
                    "parser appends trailing NUL outside binary length");

    if (ctx.pending_tasks[0].data) {
        task_free(ctx.pending_tasks[0].data);
    }

    if (passed != 7) {
        return 1;
    }
    printf("checkin response parser tests passed\n");
    return 0;
}
