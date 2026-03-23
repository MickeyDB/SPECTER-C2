/* SPECTER Implant Linker Script
 * Produces a single .text section PIC blob with no CRT startup.
 */

ENTRY(implant_entry)

SECTIONS
{
    . = 0;

    .text :
    {
        *(.text.entry)       /* Entry point first */
        *(.text*)            /* All code */
        *(.rdata*)           /* Read-only data (strings, constants) */
        *(.data*)            /* Initialized data */
        *(.bss*)             /* Uninitialized data */

        /* .pdata (RUNTIME_FUNCTION array) and .xdata (UNWIND_INFO)
           are kept in the PIC blob so the implant can register them
           with RtlAddFunctionTable for proper stack unwinding. */
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
    }
}
