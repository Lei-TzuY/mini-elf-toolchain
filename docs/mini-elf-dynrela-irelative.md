# mini-elf-dynrela-irelative

`mini-elf-dynrela-irelative` is a bounded ELF64 x86-64 dynamic-loader foundation tool for validating and simulating `R_X86_64_IRELATIVE` entries from the runtime-facing `DT_RELA` table.

```text
mini-elf-dynrela-irelative --load-bias 0x70000000 libsample.so
mini-elf-dynrela-irelative --load-bias=1879048192 first.so second.so
```

The tool requires an `ET_DYN` image, validates the program-header table, locates exactly one `PT_DYNAMIC`, requires a terminated and coherent `DT_RELA` / `DT_RELASZ` / `DT_RELAENT` tuple, and maps the relocation table only through file-backed `PT_LOAD` ranges. ELF64 RELA entries must be 24 bytes.

For each `R_X86_64_IRELATIVE`, the symbol index must be zero. The relocation target is treated as an 8-byte runtime slot and must lie in a writable `PT_LOAD` memory range. The signed RELA addend is interpreted as the object-relative resolver address; negative addends are rejected, and the resolver byte must lie in an executable, file-backed `PT_LOAD`. With explicit load bias `B`, the tool checks both runtime addresses `B + r_offset` and `B + A` for unsigned overflow and reports them deterministically. Other dynamic RELA kinds are ignored rather than pretending to resolve symbols.

Focused integration coverage creates a real GNU-linked shared object containing an `R_X86_64_IRELATIVE` relocation and verifies the kind with GNU `readelf -rW`. Malformed regressions cover non-zero symbol indices, resolver addresses outside executable loads, targets outside writable loads, negative resolver addends, and multi-input stdout atomicity.

This slice does not call IFUNC resolvers, mutate a process image, resolve dependencies or symbols, apply `GLOB_DAT`/`JUMP_SLOT`, or combine RELA/REL/RELR into a complete loader. Resolver invocation order and runtime side effects remain outside scope.
