# `mini-elf-lsda-relative`

`mini-elf-lsda-relative` adds one bounded ET_DYN exception-metadata slice on top of the existing GNU/Itanium LSDA type-table work. It validates an allocatable `.gcc_except_table` using omitted LPStart, `DW_EH_PE_indirect | DW_EH_PE_pcrel | DW_EH_PE_sdata4` (`0x9b`) type-table entries, ULEB128 call-site metadata, and bounded action chains, then resolves each referenced positive type-table entry to its indirect pointer slot.

For ET_DYN images the pointer stored in that slot commonly does not contain its runtime value in the file. This tool therefore requires a matching `.rela.dyn` relocation whose `r_offset` is exactly the validated slot address, whose relocation type is `R_X86_64_RELATIVE`, and whose symbol index is zero. The RELA addend is interpreted as the object-relative target virtual address. Runtime load bias remains symbolic, so output reports the target as `B+<address>` rather than pretending that the image has already been loaded.

The complete 8-byte pointer slot and the object-relative target must both map into file-backed `PT_LOAD` ranges. Program-header, section-header, `.gcc_except_table`, `.rela.dyn`, ULEB128/SLEB128, action-chain, type-index, PC-relative slot arithmetic, RELA entry-size, relocation type/symbol, signed addend conversion, and target mapping are all checked before output. Multiple input paths are validated before any stdout is emitted.

```sh
mini-elf-lsda-relative ./libexample.so
mini-elf-lsda-relative ./libone.so ./libtwo.so
```

The slice deliberately does **not** implement a general dynamic loader. It does not apply arbitrary dynamic relocations, resolve dynamic symbols, inspect RTTI object layout, compare thrown types, execute landing pads, or run a personality routine. It accepts only ET_DYN, `.rela.dyn`, and `R_X86_64_RELATIVE` for the validated LSDA type slots; unsupported or ambiguous relocation state fails closed.

Focused regressions build a real GNU `as` + `ld -shared` image containing a `0x9b` type-table entry and a local indirect type slot that GNU `ld` represents with `R_X86_64_RELATIVE`. GNU `readelf -rW` supplies differential relocation evidence and `readelf -sW` independently supplies the expected slot and target virtual addresses. Malformed coverage includes a wrong relocation type, a nonzero symbol index, a negative RELA addend, an unmapped target, a truncated `.rela.dyn` entry envelope, and malformed-later-input stdout atomicity.
