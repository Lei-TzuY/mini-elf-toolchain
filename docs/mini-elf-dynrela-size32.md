# `mini-elf-dynrela-size32`

`mini-elf-dynrela-size32` validates one bounded ELF64 x86-64 dynamic-loader contract: `R_X86_64_SIZE32` relocations carried by an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-size32 <input>...
```

The validator requires little-endian ELF64 x86-64 `ET_DYN`, exactly one `PT_DYNAMIC`, a terminated dynamic table, SysV `DT_HASH`, bounded `DT_SYMTAB`/`DT_STRTAB`, and a well-formed `DT_RELA` table. Each `R_X86_64_SIZE32` entry must use a non-zero in-range dynamic symbol index and its complete four-byte destination must lie in writable `PT_LOAD` memory.

For a same-image defined symbol, the bounded slice evaluates the x86-64 ABI expression `Z + A`, where `Z` is `st_size` and `A` is the signed RELA addend. The result must fit exactly in `u32`; negative values and values above `u32::MAX` are rejected rather than truncated. Absolute and TLS symbols are rejected because their semantics belong to separate slices.

Undefined dynamic symbols are reported as external symbolic `Z+A` bindings. Dependency lookup, symbol interposition/versioning, TLS, IFUNC execution, and actually writing relocated memory are intentionally outside this validator.

Validation is atomic across multiple inputs: every file is validated before stdout is emitted, so a malformed later input cannot leave partial successful output.

Focused integration coverage builds a real GNU `as`/`ld -shared --hash-style=sysv` fixture using `.long external@SIZE`, verifies `R_X86_64_SIZE32` independently with GNU `readelf -rW`, and covers same-image negative addends, invalid symbol indices, non-writable targets, unsigned-32 overflow/underflow, and multi-input stdout atomicity.
