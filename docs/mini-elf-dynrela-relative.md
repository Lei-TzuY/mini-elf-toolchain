# mini-elf-dynrela-relative

`mini-elf-dynrela-relative` is a bounded ELF64 x86-64 dynamic-loader foundation tool for inspecting and simulating `R_X86_64_RELATIVE` entries from the runtime-facing `DT_RELA` table.

```text
mini-elf-dynrela-relative --load-bias 0x70000000 libsample.so
mini-elf-dynrela-relative --load-bias=1879048192 first.so second.so
```

The tool discovers `DT_RELA`, `DT_RELASZ`, and `DT_RELAENT` through `PT_DYNAMIC`, requires the complete tag tuple and the ELF64 24-byte entry size, maps the relocation table only through file-backed `PT_LOAD` ranges, and scans every dynamic RELA entry. For each `R_X86_64_RELATIVE`, the symbol index must be zero and the 8-byte relocation target must fit inside a `PT_LOAD` memory range.

Simulation uses the x86-64 relative-relocation formula `B + A`, where `B` is the explicit load bias and `A` is the signed RELA addend. Positive addition and negative subtraction are checked rather than wrapping; a result outside the `u64` address space is rejected. Non-relative RELA entries are intentionally ignored by this bounded tool rather than pretending to resolve symbols or apply broader relocation semantics.

All inputs are validated before stdout is emitted, preserving multi-input atomicity. Focused integration coverage builds a real GNU-linked shared object with a local pointer that produces `R_X86_64_RELATIVE`, checks the relocation kind against GNU `readelf -rW`, verifies the simulated `B + A` value, and covers non-zero relative symbols, relocation-target overflow, arithmetic overflow, malformed `DT_RELAENT`, and later-input stdout atomicity.

This slice does not mutate an ELF file, build a complete in-memory image, resolve dependencies, apply `R_X86_64_GLOB_DAT`/`JUMP_SLOT`, or combine RELA with REL/RELR into a full loader. Those remain separate future vertical slices.
