# `mini-elf-lsda-ttype`

`mini-elf-lsda-ttype` extends the checked GNU/Itanium exception-metadata work with one bounded type-table slice. It locates one allocatable `.gcc_except_table` section, accepts omitted LPStart plus GNU's fixed-width `DW_EH_PE_indirect | DW_EH_PE_pcrel | DW_EH_PE_sdata4` type-table encoding (`0x9b`), decodes the ULEB128 type-table base offset, parses the existing ULEB128 call-site/action structure, and validates positive action filters as 1-based indices into 4-byte type-table entries.

```sh
mini-elf-lsda-ttype ./app
mini-elf-lsda-ttype ./app ./libexample.so
```

The type-table base is computed with checked `usize` arithmetic from the cursor immediately following the encoded type-table offset. The declared call-site table must end no later than that base. Positive action filters reserve fixed-width entries backwards from the type-table base, matching the Itanium ABI layout used by GNU exception tables. The highest referenced type index determines the earliest required entry; required entries must remain inside `.gcc_except_table` and must not overlap the call-site table or decoded action records.

For each validated positive filter, the tool now applies the declared `0x9b` pointer semantics instead of stopping at the raw field. The 4-byte signed value is added to the type-entry field's own virtual address with checked signed arithmetic to obtain the indirect pointer-slot address. That full 8-byte slot must be contained in one file-backed `PT_LOAD`; the tool reads the little-endian pointer stored there and requires the resulting target address to map back into a file-backed `PT_LOAD` as well. Output reports the 1-based type index, bounded entry envelope, raw signed displacement, resolved slot address, and resolved indirect target.

This remains an offline structural/link-time validator. It deliberately does **not** apply dynamic relocations or load bias, inspect C++ RTTI object layout, compare thrown types, execute landing pads, or implement a personality routine. Therefore an image whose indirect slot depends on unapplied runtime dynamic relocations is rejected rather than guessed. Negative type filters remain unsupported because they require exception-specification tables and language-level semantics.

ELF program-header and section-table bounds, `.gcc_except_table` file bounds/allocation, ULEB128/SLEB128 widths, type-table-base arithmetic, call-site envelopes, action offsets/chains, type-index multiplication/subtraction, action/type-table overlap, PC-relative pointer arithmetic, full pointer-slot containment, indirect target mapping, and multi-input stdout atomicity are validated before output.

Focused regressions use a real GNU `as` + `ld --eh-frame-hdr` executable with a genuine PC-relative type entry and indirect pointer slot. GNU `readelf -x .gcc_except_table` provides byte-level differential evidence, while `readelf -sW` independently supplies the expected pointer-slot and target symbol addresses. Malformed cases cover PC-relative underflow, an unmapped pointer slot, an unmapped indirect target, a type-table base outside the section, a positive type index that overlaps earlier table data, a negative filter, and a malformed later input that must leave stdout empty.

Broader DW_EH_PE encodings, non-omitted LPStart, exception-specification filters, dynamic relocation application, RTTI object validation/matching, and language-specific exception behavior remain outside this bounded slice.
