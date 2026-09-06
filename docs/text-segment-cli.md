# Bounded GNU `-Ttext-segment` compatibility

The static linker accepts GNU ld's equals-form text-segment origin option through the existing checked image-base path:

```sh
mini-elf-toolchain link -o app -Ttext-segment=0x800000 start.o
```

The address accepts the same unsigned 64-bit hexadecimal or decimal syntax as `--image-base`. For this linker's current static ELF layout, it selects the virtual address of the first load segment and feeds the existing permission-aware layout and executable emitter. GNU ld is used as a differential oracle for that externally visible segment-origin contract; later section offsets inside the segment need not be byte-for-byte identical to GNU's default linker script.

`-Ttext-segment=<address>` is recognized before attached `-T<script>` parsing, so it is not treated as a linker-script filename. Empty, malformed, and overflowing addresses are rejected before link-input or output I/O. Combining it with another explicit image-base option is rejected as a duplicate image-base selection, and combining it with a linker script that selects the image base is rejected as a conflicting source.

This slice intentionally does not implement general `-Ttext`, `-Tdata`, `-Tbss`, arbitrary section-address controls, GNU's complete default-script layout, or any additional linker-script grammar.
