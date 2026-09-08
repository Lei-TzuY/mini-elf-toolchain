# mini-elf-dynseg

`mini-elf-dynseg` inspects ELF64 x86-64 runtime dynamic metadata through the program-header table instead of relying on section headers.

```text
mini-elf-dynseg <input>...
```

The tool discovers at most one `PT_DYNAMIC` segment, requires the ELF header's program-header entry size to match the 56-byte ELF64 `Elf64_Phdr` layout before walking the table, validates every program-header file range and checked `p_vaddr + p_memsz` virtual range, requires 16-byte `Elf64_Dyn` entries and a terminating `DT_NULL`, and decodes the entries up to that terminator. For string-valued tags such as `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, and `DT_RUNPATH`, `DT_STRTAB` plus `DT_STRSZ` are resolved by mapping the virtual string-table range through a file-backed `PT_LOAD` segment. Duplicate `DT_STRTAB`/`DT_STRSZ`, unmapped virtual ranges, out-of-range string offsets, missing NUL termination, file-range overflow, virtual-range overflow, mismatched program-header entry sizing, and malformed segment sizing are rejected before stdout is emitted.

Multiple inputs are fully inspected before any report is printed, so a malformed later input cannot leave partial stdout from an earlier file.

Regression coverage uses GNU `as` and `ld -shared` to create a real shared object and compares core facts with `GNU readelf -dW`, including `SONAME`, `STRTAB`, `SYMTAB`, and `DT_NULL`. Focused malformed-input coverage removes every `DT_NULL` terminator, forces a `PT_DYNAMIC` file-range overflow, supplies a non-ELF64 program-header entry size, and overflows a program-header virtual memory range.

This is a bounded dynamic-link foundation. It does not load dependencies, apply dynamic relocations, resolve symbols at runtime, interpret symbol versions, or emit shared objects.