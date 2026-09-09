# `mini-elf-eh-frame`

`mini-elf-eh-frame` inspects the ELF64 x86-64 `PT_GNU_EH_FRAME` program header as a bounded dynamic-loader foundation.

```sh
mini-elf-eh-frame ./app
mini-elf-eh-frame --load-bias 0x100000 ./app
mini-elf-eh-frame --load-bias=0x100000 ./app
```

For each input, the tool validates the program-header table with checked file and virtual ranges, requires at most one `PT_GNU_EH_FRAME` segment, requires a file-backed `.eh_frame_hdr`, and verifies that its virtual range is contained in a `PT_LOAD` memory range. The header version must be GNU version `1`.

This bounded slice also validates the GNU `ld --eh-frame-hdr` encoding tuple used by the x86-64 fixtures: `DW_EH_PE_pcrel | DW_EH_PE_sdata4` (`0x1b`) for the `.eh_frame` pointer, `DW_EH_PE_udata4` (`0x03`) for the FDE count, and `DW_EH_PE_datarel | DW_EH_PE_sdata4` (`0x3b`) for the binary-search table. The inspector decodes the 32-bit FDE count and uses checked arithmetic to require the complete `12 + count * 8` header/table envelope to fit in the file-backed `PT_GNU_EH_FRAME` segment before reporting it.

When `--load-bias` is provided, the tool reports the checked runtime range after applying the bias. Runtime-start and runtime-end arithmetic is rejected on overflow. Multiple inputs are fully validated before stdout is emitted, so a malformed later input cannot leave partial output.

The focused regression suite builds a real GNU `ld --eh-frame-hdr` shared object and differentially compares both the `GNU_EH_FRAME` program-header virtual range from `readelf -lW` and the decoded FDE count against GNU `readelf -wf`. It also covers duplicate segments, malformed header versions, unsupported pointer encodings, a declared FDE table that exceeds the file-backed segment, virtual-range overflow, load-bias overflow, and multi-input stdout atomicity.

This slice intentionally stops at validating the common GNU x86-64 `.eh_frame_hdr` envelope and table sizing. It does not yet decode individual binary-search table entries, dereference the encoded `.eh_frame` pointer, parse CIE/FDE records, interpret DWARF call-frame instructions, or perform stack unwinding. Other DWARF pointer-encoding tuples are rejected rather than partially decoded.
