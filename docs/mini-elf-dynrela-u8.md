# `mini-elf-dynrela-u8`

`mini-elf-dynrela-u8` validates one bounded ELF64 x86-64 dynamic-loader contract: same-image `R_X86_64_8` relocations in an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-u8 --load-bias <address> <input>...
```

The validator requires checked `PT_DYNAMIC` metadata for `DT_RELA`, SysV `DT_HASH`, `DT_SYMTAB`, and `DT_STRTAB`. For every relocation of type 14 (`R_X86_64_8`), it requires a non-zero in-range dynamic symbol index, a one-byte relocation target fully contained in a writable `PT_LOAD`, and a same-image defined symbol whose value is mapped by a load segment. Absolute and TLS symbols are rejected because their loader semantics are outside this slice.

The relocation is evaluated as the ABI absolute formula `S + A`, using the explicit load bias to form the runtime symbol address. All load-bias and signed-addend arithmetic is checked. The final value must fit exactly in an unsigned 8-bit field; truncation is rejected.

The tool validates every input before producing stdout, so a malformed later input cannot leave partial output. Focused tests use GNU `as` and `ld` to create the dynamic image and GNU `readelf -rW` to independently recognize the patched `R_X86_64_8` relocation. Regressions cover invalid dynamic symbol indices, non-writable targets, negative addends, unsigned-8 overflow, and multi-input stdout atomicity.

This checkpoint deliberately does not implement dependency lookup, symbol interposition/versioning, TLS, IFUNC execution, or actual relocation writes into a process image.
