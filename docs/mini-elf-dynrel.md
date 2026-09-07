# `mini-elf-dynrel`

`mini-elf-dynrel` inspects an ELF64 x86-64 runtime `DT_REL` relocation table through the program-header path rather than section headers.

```text
mini-elf-dynrel <input>...
```

The inspector locates at most one `PT_DYNAMIC`, requires a NUL-terminated dynamic table, and treats `DT_REL`, `DT_RELSZ`, and `DT_RELENT` as one all-or-nothing tuple. ELF64 `DT_RELENT` must be 16 bytes and `DT_RELSZ` must be an exact multiple of that entry size.

The relocation table must map completely through a file-backed `PT_LOAD` range. Virtual-address, file-offset, table-size, and per-entry arithmetic is checked before slicing. Duplicate `DT_REL`, `DT_RELSZ`, or `DT_RELENT` tags are rejected. Each entry prints the relocation offset, raw `r_info`, decoded x86-64 relocation type, symbol index, and resolved dynamic-symbol name.

For nonzero relocation symbols, resolution uses `DT_SYMTAB` / `DT_SYMENT` and `DT_STRTAB` / `DT_STRSZ`, with SysV `DT_HASH.nchain` providing the checked dynamic-symbol count. ELF64 `DT_SYMENT` must be 24 bytes, the complete symbol and string tables must be file-backed through `PT_LOAD`, symbol indices must be within `nchain`, name offsets must be within `DT_STRSZ`, and names must terminate with NUL before the dynamic string table ends. GNU-hash-only symbol bounds are intentionally outside this slice.

Multiple inputs are validated completely before stdout is emitted, so a malformed later file cannot leave partial output from earlier inputs.

This is a bounded inspection foundation only. It does not apply relocations, interpret implicit addends from target memory, support GNU-hash-only symbol bounds, inspect `DT_RELA`/`DT_RELR`, or construct PLT/GOT/runtime-loader state.
