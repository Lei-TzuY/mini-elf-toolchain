# `mini-elf-interp`

`mini-elf-interp` inspects the ELF64 x86-64 `PT_INTERP` program header as a bounded dynamic-loader foundation.

```sh
mini-elf-interp ./a.out
```

The tool validates the ELF and program-header table with checked arithmetic, validates every program-header file range, accepts at most one `PT_INTERP`, and requires the interpreter segment to appear before any `PT_LOAD`. A present interpreter path must have a non-empty file range, end in exactly one terminating NUL after the path, contain no embedded NUL, and decode as UTF-8 before it is rendered. Multiple inputs are validated before stdout is emitted, preserving stdout atomicity when a later input is malformed.

Focused tests build a real GNU-linked executable with `ld --dynamic-linker` and compare the reported pathname with GNU `readelf -lW`. Malformed coverage includes duplicate interpreter segments, missing NUL termination, checked file-range overflow, and atomic multi-input failure.

This slice is intentionally read-only. It does not open or map the interpreter, construct a process image, apply relocations, resolve dependencies, honor `DT_NEEDED`, transfer control, or mutate the ELF file.
