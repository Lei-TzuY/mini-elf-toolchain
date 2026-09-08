# mini-elf-dynflags

`mini-elf-dynflags` inspects ELF64 x86-64 `DT_FLAGS` and `DT_FLAGS_1` policy bits through the runtime `PT_DYNAMIC` segment.

```text
mini-elf-dynflags <input>...
```

The tool validates the program-header table and every file-backed segment range with checked arithmetic, accepts at most one `PT_DYNAMIC`, requires 16-byte `Elf64_Dyn` entries and a terminating `DT_NULL`, and rejects duplicate `DT_FLAGS` or `DT_FLAGS_1` entries.

`DT_FLAGS` decoding covers `ORIGIN`, `SYMBOLIC`, `TEXTREL`, `BIND_NOW`, and `STATIC_TLS`. `DT_FLAGS_1` decoding covers the common runtime-policy flags from `NOW` through `PIE`, including `GLOBAL`, `GROUP`, `NODELETE`, `INITFIRST`, `NOOPEN`, `ORIGIN`, `INTERPOSE`, `NODEFLIB`, `NODUMP`, `NODIRECT`, `GLOBAUDIT`, and `SINGLETON`. Bits outside the recognized set are preserved numerically instead of being silently discarded.

Multiple inputs are fully inspected before stdout is emitted, so a malformed later input cannot leave a partial successful report behind.

Regression coverage builds a real GNU `ld -shared -z now -z origin` fixture and compares policy names with `GNU readelf -dW`. Focused malformed-input coverage rejects duplicate `DT_FLAGS` and checked `PT_DYNAMIC` file-range overflow.

This remains a bounded dynamic-link foundation: it reports loader policy metadata but does not load dependencies, resolve runtime symbols, apply relocations, mutate ELF files, or execute initialization code.
