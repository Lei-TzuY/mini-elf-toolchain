# `mini-elf-note`

`mini-elf-note` is a bounded ELF64 x86-64 `PT_NOTE` inspector. It walks program headers rather than section headers, validates note-segment file ranges and alignment with checked arithmetic, decodes the 4-byte-aligned ELF note records, and recognizes GNU `NT_GNU_BUILD_ID` notes.

```sh
cargo run --bin mini-elf-note -- ./libexample.so
```

For each note record the tool reports the containing `PT_NOTE` segment, note index, owner name, type, and descriptor size. A note with owner `GNU` and type `NT_GNU_BUILD_ID` is additionally rendered as a hexadecimal GNU build ID.

The parser rejects malformed program-header ranges, `p_filesz > p_memsz`, invalid non-trivial segment alignment, file/virtual alignment incongruence, truncated note headers, overflowing or out-of-segment name/descriptor ranges, note padding that escapes the segment, empty GNU build IDs, and multiple GNU build-id notes. Multi-input inspection is output-atomic: all inputs are validated before any stdout is emitted.

This slice is intentionally inspection-only. It does not synthesize build IDs, rewrite notes, interpret GNU property payloads, construct a runtime image, or apply dynamic relocations. Focused tests use GNU `as` + `ld --build-id=sha1` fixtures and compare the reported ID with `readelf -nW`, alongside malformed-range and stdout-atomicity regressions.
