# mini-elf-dynsym

`mini-elf-dynsym` is a checked ELF64 x86-64 dynamic-symbol inspector that follows runtime-facing ELF metadata rather than section headers.

```text
mini-elf-dynsym <input>...
```

For each input it reads `PT_DYNAMIC`, requires the `DT_SYMTAB` / `DT_SYMENT` / `DT_STRTAB` / `DT_STRSZ` tuple, and uses SysV `DT_HASH.nchain` as the bounded dynamic-symbol count. Symbol and string-table virtual addresses are mapped only through file-backed `PT_LOAD` ranges. ELF64 symbol entries must use the 24-byte ABI size, and every symbol name offset must remain inside `DT_STRSZ` with a NUL terminator before the end of the mapped string table.

The output includes symbol value, size, type, binding, visibility, section index and name. Multiple inputs are fully validated before stdout is emitted, so a malformed later input cannot leave partial output.

This is deliberately a bounded dynamic-link foundation. GNU-hash-only symbol counting, symbol version tables, relocation application, PLT/GOT loading policy and dynamic-loader behavior are outside this tool's current scope.
