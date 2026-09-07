# mini-elf-relro

`mini-elf-relro` inspects ELF64 x86-64 `PT_GNU_RELRO` program-header ranges as a bounded dynamic-loader foundation.

```text
mini-elf-relro [--load-bias <address>] <input>...
```

The tool validates the ELF and program-header table, checks every program-header file range with checked arithmetic, and requires each `PT_GNU_RELRO` virtual-memory range to be fully contained in a `PT_LOAD` memory range. A malformed RELRO range, overflowing virtual-memory range, invalid program-header file range, or load-segment range overflow is rejected before stdout is emitted.

Without `--load-bias`, the report prints the link-time RELRO virtual range. With `--load-bias` (decimal or `0x` hexadecimal), it additionally computes the runtime start/end range using checked arithmetic and rejects runtime-address overflow. Multiple inputs are completely validated before any report is printed, preserving stdout atomicity when a later file is malformed.

Regression coverage creates a real GNU-linked shared object with `ld -shared -z relro` and compares the reported link-time range with `GNU readelf -lW`. Focused malformed-input tests cover RELRO virtual-range overflow, a RELRO segment moved outside every `PT_LOAD` memory range, load-bias runtime-address overflow, and malformed-later-input atomicity.

This slice only inspects and validates the protection range. It does not call `mprotect`, construct a process image, apply relocations, load dependencies, resolve symbols, or mutate the ELF file.
