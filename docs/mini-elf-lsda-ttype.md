# `mini-elf-lsda-ttype`

`mini-elf-lsda-ttype` extends the checked GNU/Itanium exception-metadata work with one bounded type-table slice. It locates one allocatable `.gcc_except_table` section, accepts omitted LPStart plus GNU's fixed-width `DW_EH_PE_indirect | DW_EH_PE_pcrel | DW_EH_PE_sdata4` type-table encoding (`0x9b`), decodes the ULEB128 type-table base offset, parses the existing ULEB128 call-site/action structure, and validates positive action filters as 1-based indices into 4-byte type-table entries.

```sh
mini-elf-lsda-ttype ./app
mini-elf-lsda-ttype ./app ./libexample.so
```

The type-table base is computed with checked `usize` arithmetic from the cursor immediately following the encoded type-table offset. The declared call-site table must end no later than that base. Positive action filters reserve fixed-width entries backwards from the type-table base, matching the Itanium ABI layout used by GNU exception tables. The highest referenced type index determines the earliest required entry; required entries must remain inside `.gcc_except_table` and must not overlap the call-site table or decoded action records.

This slice reports each validated positive filter with its 1-based type index, bounded `[start,end)` entry envelope, and raw signed 32-bit field. It deliberately does **not** apply PC-relative or indirect pointer semantics to that raw value, resolve RTTI objects, compare thrown types, execute landing pads, or implement a personality routine. Negative type filters remain unsupported because they require exception-specification tables and language-level semantics.

ELF section-table bounds, section-name lookup, `.gcc_except_table` file bounds/allocation, ULEB128/SLEB128 widths, type-table-base arithmetic, call-site envelopes, action offsets/chains, type-index multiplication/subtraction, action/type-table overlap, and multi-input stdout atomicity are validated before output.

Focused regressions use a real GNU `as` + `ld -shared --eh-frame-hdr` image and compare the exact `.gcc_except_table` bytes against GNU `readelf -x`. Malformed cases cover a type-table base outside the section, a positive type index that pushes required entries into earlier table data, a negative filter, an action chain that reaches the type-table region, and a malformed later input that must leave stdout empty.

Broader DW_EH_PE encodings, non-omitted LPStart, exception-specification filters, pointer-target validation, RTTI matching, and language-specific exception behavior remain outside this bounded slice.
