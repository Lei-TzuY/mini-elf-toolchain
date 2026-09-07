# mini-elf-dynrel-relative

`mini-elf-dynrel-relative` is a bounded ELF64 x86-64 dynamic-loader foundation tool for inspecting and simulating `R_X86_64_RELATIVE` entries from the runtime-facing `DT_REL` table.

```text
mini-elf-dynrel-relative --load-bias 0x70000000 libsample.so
mini-elf-dynrel-relative --load-bias=1879048192 first.so second.so
```

The tool discovers `DT_REL`, `DT_RELSZ`, and `DT_RELENT` through `PT_DYNAMIC`, requires the complete tag tuple and the ELF64 16-byte entry size, and maps the relocation table only through file-backed `PT_LOAD` ranges. For each `R_X86_64_RELATIVE`, the symbol index must be zero and the 8-byte relocation target must itself be file-backed so the ELF64 implicit addend can be read safely.

Simulation uses the x86-64 REL relative-relocation formula `B + A`, where `B` is the explicit load bias and `A` is the signed 64-bit value stored at the relocation target before relocation. Positive addition and negative subtraction are checked rather than wrapping; a result outside the `u64` address space is rejected.

All inputs are validated before stdout is emitted, preserving multi-input atomicity. Focused integration coverage builds a real GNU-linked shared object containing `R_X86_64_RELATIVE`, converts its dynamic relocation metadata to the ABI-equivalent `DT_REL` form while materializing the addend in the target word, checks the relocation kind with GNU `readelf --use-dynamic -rW`, verifies the simulated value, and covers non-zero relative symbols, unbacked/overflowing targets, arithmetic overflow, malformed `DT_RELENT`, and later-input stdout atomicity.

This slice does not mutate an ELF file, build a complete in-memory process image, resolve dependencies, apply non-relative `DT_REL` entries, or combine REL with RELA/RELR into a complete dynamic loader. Those remain separate vertical slices.
