# `mini-elf-phdr`

`mini-elf-phdr` inspects the ELF64 x86-64 `PT_PHDR` program header as a bounded dynamic-loader foundation.

```sh
mini-elf-phdr ./app
mini-elf-phdr --load-bias 0x100000 ./app
```

The tool validates program-header file ranges with checked arithmetic, requires at most one `PT_PHDR`, and when present requires that it exactly describe the ELF program-header table: its file offset must equal `e_phoff`, and its file/memory sizes must equal `e_phnum * sizeof(Elf64_Phdr)`. The described virtual range must be contained in a `PT_LOAD` memory range.

`--load-bias` accepts decimal or `0x` hexadecimal unsigned 64-bit addresses. The reported runtime interval is computed with checked arithmetic so address overflow is rejected. Multiple inputs are fully inspected before stdout is emitted, preserving atomic output on malformed later inputs.

This slice does not construct a process image, map segments, apply relocations, resolve dependencies, or transfer control. It only validates and reports the runtime-facing program-header-table range needed by later loader work.
