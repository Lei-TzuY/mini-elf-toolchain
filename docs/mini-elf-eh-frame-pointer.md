# `mini-elf-eh-frame-pointer`

`mini-elf-eh-frame-pointer` validates the GNU x86-64 `.eh_frame_hdr` pointer to `.eh_frame` as a bounded dynamic-loader/unwind foundation.

```sh
mini-elf-eh-frame-pointer ./app
mini-elf-eh-frame-pointer --load-bias 0x100000 ./app
```

The command accepts ELF64 x86-64 inputs validated by the shared ELF header parser. It requires at most one `PT_GNU_EH_FRAME` segment and checks all program-header file and virtual ranges with checked arithmetic. The GNU EH-frame segment must be contained in a `PT_LOAD` memory range and provide at least the version/encoding prefix plus the four-byte pointer field.

This bounded slice supports the GNU x86-64 `.eh_frame` pointer encoding `DW_EH_PE_pcrel | DW_EH_PE_sdata4` (`0x1b`). The signed 32-bit displacement is decoded relative to the virtual address of the encoded pointer field itself. Both positive overflow and negative underflow are rejected. The resolved link-time `.eh_frame` address must lie inside the file-backed portion of a `PT_LOAD`; a pointer into unmapped space or only zero-fill memory is rejected.

`--load-bias` additionally reports the relocated runtime `.eh_frame` address using checked `u64` addition. This does not change the PC-relative decode: both the pointer field and its target receive the same load bias.

The focused regression suite builds a real GNU shared object with `as` and `ld --eh-frame-hdr`, differentially compares the decoded address with GNU `readelf -SW`, and covers signed-pointer underflow, a decoded target outside all file-backed load ranges, load-bias overflow, and multi-input stdout atomicity.

Full `.eh_frame` CIE/FDE parsing and DWARF unwinding remain outside this slice.
