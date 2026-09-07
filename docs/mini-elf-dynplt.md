# mini-elf-dynplt

`mini-elf-dynplt` inspects the runtime PLT relocation table described by an ELF64 x86-64 file's `PT_DYNAMIC` metadata.

```sh
mini-elf-dynplt libexample.so
mini-elf-dynplt first.so second.so
```

The bounded slice requires `DT_JMPREL`, `DT_PLTRELSZ`, and `DT_PLTREL` to appear together. `DT_PLTREL` must select `DT_RELA`; `DT_REL` PLT relocations are intentionally outside scope. The relocation table must be fully backed by a file-backed `PT_LOAD` range and `DT_PLTRELSZ` must be a multiple of the 24-byte ELF64 `Rela` entry size.

For nonzero relocation symbol indices, names are resolved through `DT_SYMTAB`, `DT_SYMENT`, `DT_STRTAB`, and `DT_STRSZ`, with the dynamic-symbol count bounded by SysV `DT_HASH.nchain`. Symbol/string ranges, arithmetic, symbol indices, and NUL termination are checked before output is committed. Multiple inputs are validated before any stdout is emitted, so a malformed later input leaves stdout empty.

This tool is inspection-only. It does not apply relocations, construct a PLT/GOT, perform symbol interposition, load shared objects, or implement `DT_REL`, `DT_RELR`, lazy binding, or a runtime loader.
