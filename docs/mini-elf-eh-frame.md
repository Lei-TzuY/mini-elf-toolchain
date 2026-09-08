# `mini-elf-eh-frame`

`mini-elf-eh-frame` inspects the ELF64 x86-64 `PT_GNU_EH_FRAME` program header as a bounded dynamic-loader foundation.

```sh
mini-elf-eh-frame ./app
mini-elf-eh-frame --load-bias 0x100000 ./app
mini-elf-eh-frame --load-bias=0x100000 ./app
```

For each input, the tool validates the program-header table with checked file and virtual ranges, requires at most one `PT_GNU_EH_FRAME` segment, requires a non-empty file-backed header, and verifies that its virtual range is contained in a `PT_LOAD` memory range. The first byte of the referenced `.eh_frame_hdr` must be the GNU version value `1`.

When `--load-bias` is provided, the tool reports the checked runtime range after applying the bias. Runtime-start and runtime-end arithmetic is rejected on overflow. Multiple inputs are fully validated before stdout is emitted, so a malformed later input cannot leave partial output.

The focused regression suite builds a real GNU `ld --eh-frame-hdr` shared object and differentially compares the `GNU_EH_FRAME` program-header virtual range with `readelf -lW`. It also covers duplicate segments, malformed header versions, virtual-range overflow, load-bias overflow, and multi-input stdout atomicity.

This slice intentionally stops at the loader-visible `PT_GNU_EH_FRAME` / `.eh_frame_hdr` envelope. It does not decode pointer encodings, binary-search tables, CIE/FDE records, DWARF call-frame instructions, or perform stack unwinding.
