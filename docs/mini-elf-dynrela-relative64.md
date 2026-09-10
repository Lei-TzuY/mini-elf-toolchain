# `mini-elf-dynrela-relative64`

`mini-elf-dynrela-relative64` validates the bounded ELF64 x86-64 `R_X86_64_RELATIVE64` relocation contract in an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-relative64 --load-bias <address> <input>...
```

The validator requires the standard `DT_RELA`, `DT_RELASZ`, and `DT_RELAENT` tuple, maps the relocation table through file-backed `PT_LOAD` ranges with checked arithmetic, and inspects relocation type 38 (`R_X86_64_RELATIVE64`). Each matching relocation must use symbol index zero and its full eight-byte destination must lie in a writable `PT_LOAD` memory range.

The reported value follows the AMD64 ABI relative-relocation formula `B + A`, where `B` is the supplied load bias and `A` is the signed RELA addend. Addition/subtraction is checked and values that would overflow or underflow `u64` are rejected instead of wrapping.

Focused integration tests build a real GNU-linked shared object, rewrite its symbol-free relative relocation to type 38, verify GNU `readelf -rW` recognizes `R_X86_64_RELATIVE64`, and cover non-zero symbol indices, non-writable targets, arithmetic overflow, malformed `DT_RELAENT`, and multi-input stdout atomicity.

This slice deliberately does not perform relocation writes, dependency lookup, symbol interposition/versioning, TLS processing, or IFUNC execution.
