# `mini-elf-tls-segment`

`mini-elf-tls-segment` is a bounded ELF64 x86-64 loader-inspection tool for the TLS program header used to describe an image's initial thread-local-storage template.

```text
mini-elf-tls-segment [--load-bias <address>] <input>...
mini-elf-tls-segment [--load-bias=<address>] <input>...
```

For each input, the tool parses the program-header table directly and reports the single `PT_TLS` segment, if present. It prints the file-backed initializer range, link-time virtual range, checked runtime range after the selected load bias, `p_filesz`, `p_memsz`, the zero-filled TLS suffix (`p_memsz - p_filesz`), and `p_align`.

The inspector fails closed when `PT_TLS` is duplicated, when the ELF/program-header or segment file ranges overflow or leave the file, when `p_filesz > p_memsz`, when TLS alignment is zero or is not a power of two, when `p_offset` and `p_vaddr` are incongruent modulo `p_align`, when the TLS virtual-memory range is not contained in a `PT_LOAD` memory range, or when load-bias arithmetic overflows. Multiple inputs are validated before stdout is emitted, so a malformed later input does not leave partial output.

The regression suite builds a real GNU `as` + `ld -shared` TLS image containing initialized `.tdata` and zero-filled `.tbss`, checks that GNU `readelf -lW` and this tool both identify the TLS segment, and exercises malformed alignment/congruence, runtime overflow, and stdout atomicity.

This slice intentionally does not allocate per-thread TLS blocks, choose a thread-pointer ABI model, apply TLS relocations, resolve dependencies, construct a process image, or mutate the ELF file.
