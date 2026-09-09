# `mini-elf-lsda-header`

`mini-elf-lsda-header` adds one bounded LSDA-structure slice on top of the repository's checked GNU `.eh_frame` exception-metadata work. It locates one allocatable `.gcc_except_table` section in an ELF64 x86-64 image and validates the first Itanium-style LSDA header envelope without interpreting landing pads, call-site entries, action records, or type tables.

```sh
mini-elf-lsda-header ./app
mini-elf-lsda-header ./app ./libexample.so
```

This slice accepts the compact GNU-compatible header tuple used by its focused fixture: omitted LPStart (`DW_EH_PE_omit` / `0xff`), omitted type table (`0xff`), and ULEB128 call-site encoding (`0x01`). The ULEB128 call-site table length is decoded with checked arithmetic and the declared table must remain fully within the file-backed `.gcc_except_table` section.

ELF section-header table bounds, the section-name string table, section-name offsets/termination, `.gcc_except_table` file ranges, section allocation flags, ULEB128 width, and table-length arithmetic are validated before slicing. Extended ELF section numbering, multiple exception-table sections, non-omitted LPStart/type tables, other call-site encodings, call-site entry decoding, actions, type tables, and language-specific exception semantics remain outside this bounded slice.

Focused regressions build a real GNU `as` / `ld -shared --eh-frame-hdr` image containing `.cfi_lsda` plus an allocatable `.gcc_except_table`. GNU `readelf -SW` supplies differential evidence for the section virtual address. Malformed coverage changes the LPStart/type-table/call-site encodings, makes the call-site table length escape the section, and verifies that a malformed later input leaves stdout empty.
