/*
 * SPECTER PIC loader smoke harness.
 *
 * Loads a raw payload produced by the builder, maps it into executable memory,
 * and calls the entry point at offset 0. This is intentionally a local lab
 * harness: it does not inject into another process and it does not detach.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (__attribute__((ms_abi)) *pic_entry_fn)(void *);

static const char *g_payload_base = NULL;

static LONG CALLBACK vectored_exception_handler(PEXCEPTION_POINTERS info)
{
    DWORD code = info && info->ExceptionRecord ? info->ExceptionRecord->ExceptionCode : 0;
    void *addr = info && info->ExceptionRecord ? info->ExceptionRecord->ExceptionAddress : NULL;

    if (code == DBG_PRINTEXCEPTION_C) {
        ULONG_PTR count = info->ExceptionRecord->NumberParameters;
        if (count >= 2) {
            ULONG_PTR len = info->ExceptionRecord->ExceptionInformation[0];
            const char *msg = (const char *)info->ExceptionRecord->ExceptionInformation[1];
            if (msg && len > 0 && len < 4096) {
                fprintf(stderr, "[pic-debug] ");
                fwrite(msg, 1, (size_t)len, stderr);
                fputc('\n', stderr);
                fflush(stderr);
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code == DBG_PRINTEXCEPTION_WIDE_C) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    fprintf(stderr, "[pic-loader] unhandled exception 0x%08lx at %p\n",
            (unsigned long)code, addr);
    if (g_payload_base && addr) {
        intptr_t rva = (const char *)addr - g_payload_base;
        if (rva >= 0) {
            fprintf(stderr, "[pic-loader] payload offset 0x%llx\n",
                    (unsigned long long)(uintptr_t)rva);
        }
    }
    fflush(stderr);
    ExitProcess(0xEE);
    return EXCEPTION_EXECUTE_HANDLER;
}

static int read_file(const char *path, unsigned char **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long len;
    unsigned char *buf;

    if (!f) {
        fprintf(stderr, "[pic-loader] failed to open %s\n", path);
        return 1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 1;
    }
    len = ftell(f);
    if (len <= 0) {
        fclose(f);
        fprintf(stderr, "[pic-loader] empty payload: %s\n", path);
        return 1;
    }
    rewind(f);

    buf = (unsigned char *)malloc((size_t)len);
    if (!buf) {
        fclose(f);
        fprintf(stderr, "[pic-loader] out of memory reading %ld bytes\n", len);
        return 1;
    }

    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        fclose(f);
        free(buf);
        fprintf(stderr, "[pic-loader] short read: %s\n", path);
        return 1;
    }
    fclose(f);

    *out = buf;
    *out_len = (size_t)len;
    return 0;
}

static DWORD parse_timeout(int argc, char **argv)
{
    for (int i = 2; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--timeout-ms") == 0) {
            return (DWORD)strtoul(argv[i + 1], NULL, 10);
        }
    }
    return 15000;
}

static size_t parse_hex_size(const char *text)
{
    if (!text) {
        return 0;
    }
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        return (size_t)strtoull(text + 2, NULL, 16);
    }
    return (size_t)strtoull(text, NULL, 16);
}

static size_t parse_size_arg(int argc, char **argv, const char *name, size_t default_value)
{
    for (int i = 2; i + 1 < argc; i++) {
        if (strcmp(argv[i], name) == 0) {
            return parse_hex_size(argv[i + 1]);
        }
    }
    return default_value;
}

static int has_flag(int argc, char **argv, const char *flag)
{
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], flag) == 0) {
            return 1;
        }
    }
    return 0;
}

static size_t page_floor(size_t value, size_t page_size)
{
    return value & ~(page_size - 1);
}

static DWORD WINAPI pic_thread_main(LPVOID param)
{
    pic_entry_fn entry = (pic_entry_fn)param;
    entry(NULL);
    return 0;
}

int main(int argc, char **argv)
{
    unsigned char *file_buf = NULL;
    size_t payload_len = 0;
    void *mem;
    HANDLE thread;
    DWORD wait_rc;
    DWORD thread_code = 0;
    DWORD timeout_ms;
    DWORD old_protect = 0;
    int protect_rx;
    int split_protect;
    size_t rw_offset;
    SYSTEM_INFO sysinfo;
    size_t page_size;
    size_t code_len;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <payload.bin> [--timeout-ms N] [--protect-rx] [--split-protect --rw-offset HEX]\n", argv[0]);
        return 2;
    }

    timeout_ms = parse_timeout(argc, argv);
    protect_rx = has_flag(argc, argv, "--protect-rx");
    split_protect = has_flag(argc, argv, "--split-protect");
    rw_offset = parse_size_arg(argc, argv, "--rw-offset", 0);
    GetSystemInfo(&sysinfo);
    page_size = (size_t)sysinfo.dwPageSize;
    if (protect_rx && split_protect) {
        fprintf(stderr, "[pic-loader] --protect-rx and --split-protect are mutually exclusive\n");
        return 2;
    }
    if (read_file(argv[1], &file_buf, &payload_len) != 0) {
        return 1;
    }

    /*
     * The flat blob contains code plus mutable data/BSS in one section, so
     * PAGE_EXECUTE_READ would fault as soon as globals are initialized.
     */
    mem = VirtualAlloc(NULL,
                       payload_len,
                       MEM_RESERVE | MEM_COMMIT,
                       split_protect ? PAGE_READWRITE : PAGE_EXECUTE_READWRITE);
    if (!mem) {
        fprintf(stderr, "[pic-loader] VirtualAlloc failed: %lu\n", GetLastError());
        free(file_buf);
        return 1;
    }

    memcpy(mem, file_buf, payload_len);
    SecureZeroMemory(file_buf, payload_len);
    free(file_buf);

    if (protect_rx) {
        if (!VirtualProtect(mem, payload_len, PAGE_EXECUTE_READ, &old_protect)) {
            fprintf(stderr, "[pic-loader] VirtualProtect RX failed: %lu\n", GetLastError());
            VirtualFree(mem, 0, MEM_RELEASE);
            return 1;
        }
        fprintf(stdout, "[pic-loader] protected payload as RX\n");
        fflush(stdout);
    }
    if (split_protect) {
        if (rw_offset == 0 || rw_offset >= payload_len) {
            fprintf(stderr, "[pic-loader] invalid split rw offset: 0x%llx for payload %llu\n",
                    (unsigned long long)rw_offset,
                    (unsigned long long)payload_len);
            VirtualFree(mem, 0, MEM_RELEASE);
            return 1;
        }
        code_len = page_floor(rw_offset, page_size);
        if (code_len == 0) {
            fprintf(stderr, "[pic-loader] split code length resolved to zero\n");
            VirtualFree(mem, 0, MEM_RELEASE);
            return 1;
        }
        if (!VirtualProtect(mem, code_len, PAGE_EXECUTE_READ, &old_protect)) {
            fprintf(stderr, "[pic-loader] VirtualProtect split RX failed: %lu\n", GetLastError());
            VirtualFree(mem, 0, MEM_RELEASE);
            return 1;
        }
        fprintf(stdout, "[pic-loader] split protection code=RX 0x0..0x%llx data=RW 0x%llx..0x%llx\n",
                (unsigned long long)code_len,
                (unsigned long long)code_len,
                (unsigned long long)payload_len);
        fflush(stdout);
    }

    g_payload_base = (const char *)mem;
    AddVectoredExceptionHandler(1, vectored_exception_handler);
    FlushInstructionCache(GetCurrentProcess(), mem, payload_len);

    fprintf(stdout, "[pic-loader] mapped %llu bytes at %p\n",
            (unsigned long long)payload_len, mem);
    fflush(stdout);

    thread = CreateThread(NULL, 0, pic_thread_main, mem, 0, NULL);
    if (!thread) {
        fprintf(stderr, "[pic-loader] CreateThread failed: %lu\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }

    wait_rc = WaitForSingleObject(thread, timeout_ms);
    if (wait_rc == WAIT_TIMEOUT) {
        fprintf(stderr, "[pic-loader] timeout after %lu ms\n", (unsigned long)timeout_ms);
        CloseHandle(thread);
        VirtualFree(mem, 0, MEM_RELEASE);
        return 124;
    }
    if (wait_rc != WAIT_OBJECT_0) {
        fprintf(stderr, "[pic-loader] WaitForSingleObject failed: %lu\n", GetLastError());
        CloseHandle(thread);
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }

    GetExitCodeThread(thread, &thread_code);
    fprintf(stdout, "[pic-loader] thread exited with code %lu\n", (unsigned long)thread_code);
    CloseHandle(thread);
    VirtualFree(mem, 0, MEM_RELEASE);
    return (int)(thread_code & 0xFF);
}
