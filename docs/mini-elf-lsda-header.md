# `mini-elf-lsda-header`

`mini-elf-lsda-header` adds one bounded LSDA-structure slice on top of the repository's checked GNU `.eh_frame` exception-metadata work. It locates one allocatable `.gcc_except_table` section in an ELF64 x86-64 image, validates the first Itanium-style LSDA header envelope, and decodes the declared call-site table as bounded ULEB128 entries without interpreting landing-pad behavior, action records, type tables, or language-specific exception semantics.

```sh
mini-elf-lsda-header ./app
mini-elf-lsda-header ./app ./libexample.so
```

This slice accepts the compact GNU-compatible header tuple used by its focused fixture: omitted LPStart (`DW_EH_PE_omit` / `0xff`), omitted type table (`0xff`), and ULEB128 call-site encoding (`0x01`). The ULEB128 call-site table length is decoded with checked arithmetic and the declared table must remain fully within the file-backed `.gcc_except_table` section.

Each declared call-site entry is then decoded strictly inside that table envelope as four ULEB128 fields: start offset, code length, landing-pad offset, and action value. Every field must terminate before the declared table end, `start + length` is checked for `u64` overflow, and the parser must consume the table exactly. Output includes a deterministic entry count plus each entry's bounded interval and raw landing-pad/action values. These offsets are intentionally not promoted to absolute code or landing-pad addresses in this slice because doing so requires the surrounding FDE/LPStart context.

ELF section-header table bounds, the section-name string table, section-name offsets/termination, `.gcc_except_table` file ranges, section allocation flags, ULEB128 width, table-length arithmetic, per-entry ULEB128 envelopes, and call-site interval arithmetic are validated before output. Extended ELF section numbering, multiple exception-table sections, non-omitted LPStart/type tables, other call-site encodings, action-record traversal, type tables, landing-pad semantics, and language-specific exception behavior remain outside this bounded slice.

Focused regressions build a real GNU `as` / `ld -shared --eh-frame-hdr` image containing `.cfi_lsda` plus an allocatable `.gcc_except_table`. GNU `readelf -SW` supplies differential evidence for the section virtual address and `readelf -x .gcc_except_table` confirms the exact header/call-site bytes consumed by the decoder. Malformed coverage changes the LPStart/type-table/call-site encodings, makes the call-site table length escape the section, truncates an entry inside the declared table, overflows `start + length`, and verifies that a malformed later input leaves stdout empty.
