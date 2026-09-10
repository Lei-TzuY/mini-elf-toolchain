# `mini-elf-dynrela-jump-slot`

`mini-elf-dynrela-jump-slot` validates a bounded ELF64 x86-64 dynamic-loader contract for `R_X86_64_JUMP_SLOT` relocations in an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-jump-slot --load-bias <address> <input>...
```

The validator follows the runtime-facing program-header path. It requires exactly one checked `PT_DYNAMIC`, a RELA-form `DT_JMPREL` table described by `DT_JMPREL`, `DT_PLTRELSZ`, and `DT_PLTREL`, plus SysV `DT_HASH`, `DT_SYMTAB`/`DT_SYMENT`, and `DT_STRTAB`/`DT_STRSZ` metadata.

For every `R_X86_64_JUMP_SLOT` entry it requires a nonzero in-range dynamic symbol index, a canonical zero RELA addend, a complete writable 8-byte `PT_LOAD` relocation target, and a named non-TLS, non-absolute dynamic symbol. The runtime target `B + r_offset` and the complete eight-byte runtime range are checked for unsigned overflow.

Undefined dynamic symbols are intentionally accepted: resolving them across dependencies is the next loader layer, not part of this validation slice. Defined same-image symbols are also accepted. The tool reports the relocation target and symbol that require runtime resolution, but it does not mutate an image, perform dependency lookup, implement symbol versioning/interposition, initialize lazy-binding PLT state, or call a resolver.

Integration coverage builds a real GNU-linked shared object with an undefined `external_target` called through the PLT and requires GNU `readelf -rW` to identify `R_X86_64_JUMP_SLOT`. Regressions cover an out-of-range dynamic symbol index, a non-writable relocation target, a nonzero addend, runtime target overflow, and output atomicity when a later input is malformed.
