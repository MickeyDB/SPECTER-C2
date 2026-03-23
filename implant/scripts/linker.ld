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
    }

    /DISCARD/ :
    {
        *(.reloc)
        *(.rsrc)
        *(.pdata)
        *(.xdata)
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
