# Bounded GNU `-Ttext-segment` compatibility

The static linker accepts GNU ld's equals-form text-segment origin option as a bounded alias for the existing checked image-base path:

```sh
mini-elf-toolchain link -o app -Ttext-segment=0x800000 start.o
```

The address accepts the same unsigned 64-bit hexadecimal or decimal syntax as `--image-base`. It feeds the existing permission-aware static layout and executable emitter; it does not add independent `.text`, `.data`, or `.bss` placement semantics.

`-Ttext-segment=<address>` is recognized before attached `-T<script>` parsing, so it is not treated as a linker-script filename. Empty, malformed, and overflowing addresses are rejected before link-input or output I/O. Combining it with another explicit image-base option is rejected as a duplicate image-base selection, and combining it with a linker script that selects the image base is rejected as a conflicting source.

This slice intentionally does not implement general `-Ttext`, `-Tdata`, `-Tbss`, arbitrary section-address options, or any additional linker-script grammar.
