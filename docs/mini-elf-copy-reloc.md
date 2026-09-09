# `mini-elf-copy-reloc`

`mini-elf-copy-reloc` validates a bounded x86-64 dynamic-loader foundation for executable `R_X86_64_COPY` relocations.

The tool accepts ELF64 `ET_EXEC` images and locates `.rela.dyn` through the section table. The relocation section must be `SHT_RELA`, must use 24-byte ELF64 RELA entries, and must link to a 24-byte-entry `SHT_DYNSYM`; the dynamic symbol table in turn must link to a bounded `SHT_STRTAB`.

For every `R_X86_64_COPY` entry, the validator requires:

- a nonzero in-range dynamic symbol index;
- a zero RELA addend;
- a defined, non-absolute `STT_OBJECT` destination symbol;
- a nonzero destination size;
- `r_offset == st_value`, matching the executable's copy-storage symbol;
- the full `[r_offset, r_offset + st_size)` destination range to fit in a writable `PT_LOAD` memory range;
- a bounded NUL-terminated UTF-8 dynamic symbol name.

All section-table, section-range, program-header, relocation, symbol-index, destination-range, and arithmetic envelopes are checked before they are used. Multi-input operation is validate-first, so a malformed later image does not leave partial stdout from earlier inputs.

A successful entry is reported as an executable destination plus `source=external`. This is deliberate: the slice validates the executable-side COPY relocation contract but does **not** pretend to perform dependency lookup, symbol-version matching, interposition, source-object mapping, byte copying, relocation ordering, or process-image mutation. Those loader behaviors require a separate bounded implementation.

## GNU differential coverage

The integration fixture builds a real shared object containing `shared_data`, then links a non-PIE GNU executable that references that object. GNU `ld` therefore emits a real `R_X86_64_COPY` relocation, and the test independently verifies its presence with `readelf -rW` before invoking this validator.

Focused malformed regressions cover an out-of-range dynamic symbol index, nonzero COPY addend, copy storage moved into a non-writable executable segment, a zero-sized destination symbol, and multi-input stdout atomicity.
