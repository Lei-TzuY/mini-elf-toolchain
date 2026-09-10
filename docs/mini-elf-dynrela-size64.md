# `mini-elf-dynrela-size64`

`mini-elf-dynrela-size64` validates one bounded ELF64 x86-64 dynamic-loader contract: `R_X86_64_SIZE64` relocations carried by an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-size64 <input>...
```

The validator requires one checked `PT_DYNAMIC`, a bounded `DT_RELA` table, SysV `DT_HASH` for the dynamic-symbol count, `DT_SYMTAB`/`DT_SYMENT`, and `DT_STRTAB`/`DT_STRSZ`. Every selected relocation must reference a nonzero in-range dynamic symbol and an eight-byte destination wholly contained in a writable `PT_LOAD`.

For a same-image defined non-TLS, non-absolute symbol, the validator evaluates the x86-64 psABI `R_X86_64_SIZE64` expression `Z + A`, where `Z` is the dynamic symbol's `st_size` and `A` is the signed RELA addend. The result must fit exactly in an unsigned 64-bit relocation field; overflow and negative results are rejected rather than truncated. Undefined symbols remain explicit symbolic external bindings because their runtime size depends on dependency lookup and interposition.

Validation is fail-closed and all inputs are validated before stdout is emitted, so malformed later inputs cannot leave partial successful output.

## Deliberate boundary

This slice does not resolve dependencies, apply symbol interposition or versioning, execute IFUNC resolvers, implement TLS, or write relocation results into a mapped process image. It only establishes the checked metadata, target-range, symbol-size, and arithmetic contract needed before those loader stages are added.
