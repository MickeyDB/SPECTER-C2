/* SPECTER Implant Linker Script
 * Produces a single flat PIC blob with implant_entry at offset 0.
 *
 * Section ordering uses PE subsection sorting ($ suffix):
 *   .text$A  — entry point (offset 0, guaranteed first)
 *   .text$B  — all other code
 *   .text$C  — read-only data (strings, constants)
 *   .text$D  — initialized data (globals)
 *   .text$E  — uninitialized data (BSS)
 *   .text$F  — exception handling tables (.pdata/.xdata)
 *
 * After the extern→static refactor, there should be ZERO .refptr
 * sections. They are discarded as a safety net.
 */

ENTRY(implant_entry)

SECTIONS
{
    . = 0;

    .text :
    {
        /* A: Entry point — must be at offset 0 */
        *(.text.entry)
        *(.text$A)

        /* B: All other code */
        *(.text$B)
        *(.text .text.*)

        /* C: Read-only data */
        *(.rdata .rdata.* .text$C)

        /* D: Initialized data */
        . = ALIGN(16);
        *(.data .data.* .text$D)

        /* E: Uninitialized data (BSS) */
        . = ALIGN(16);
        *(.bss .bss.* .text$E COMMON)

        /* F: Exception handling tables for RtlAddFunctionTable */
        . = ALIGN(8);
        __pdata_start = .;
        *(.pdata)
        __pdata_end = .;

        . = ALIGN(8);
        __xdata_start = .;
        *(.xdata)
        __xdata_end = .;
    }

    /DISCARD/ :
    {
        *(.rdata$.refptr.*)  /* MinGW pseudo-GOT — must not exist after refactor */
        *(.reloc)
        *(.rsrc)
        *(.debug*)
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.gcc_except_table*)
        *(.ctors)
        *(.dtors)
        *(.CRT*)
        *(.idata*)
        *(.didat*)
        *(.tls*)
    }
}
