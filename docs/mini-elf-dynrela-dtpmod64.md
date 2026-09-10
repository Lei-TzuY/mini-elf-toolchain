# `mini-elf-dynrela-dtpmod64`

`mini-elf-dynrela-dtpmod64` validates a bounded ELF64 x86-64 `R_X86_64_DTPMOD64` dynamic-relocation slice for `ET_DYN` images.

```text
mini-elf-dynrela-dtpmod64 --load-bias 0x70000000 --module-id 7 libtls.so
```

The validator requires checked `DT_RELA` metadata, SysV `DT_HASH` symbol bounds, a valid dynamic string table, a defined `STT_TLS` symbol, a writable eight-byte relocation target, a nonzero caller-supplied module ID, and a zero RELA addend. It checks `B + r_offset` for overflow before reporting the module-ID value that a loader would place in the slot.

This is deliberately not a complete TLS loader. Dependency lookup, symbol interposition/versioning, TLS block layout, `DTPREL64`/`TPOFF64`, TLSDESC, IFUNC execution, and memory writes remain outside this slice. Multiple inputs are validated before any stdout is emitted.

Focused integration coverage uses GNU `as`/`ld` to construct a real shared object containing `R_X86_64_DTPMOD64`, verifies GNU `readelf -rW` recognition, and exercises invalid symbol indexes, nonzero addends, non-writable targets, zero module IDs, and runtime-address overflow.
