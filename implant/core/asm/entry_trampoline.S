/* entry_trampoline.S — Guarantees implant_entry is at PIC blob offset 0.
 *
 * This file is compiled as a SEPARATE object (not part of unity.c) and
 * linked FIRST.  The linker places .text from this object before unity.o,
 * so the trampoline lands at offset 0 of the final blob.
 *
 * The trampoline is a single RIP-relative JMP — no registers clobbered,
 * no stack usage, no side effects.
 */

    .intel_syntax noprefix
    .text

    .globl _start
_start:
    jmp     implant_entry
