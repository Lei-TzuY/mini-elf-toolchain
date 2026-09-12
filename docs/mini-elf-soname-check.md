# mini-elf-soname-check

`mini-elf-soname-check <input>...` validates ELF64 x86-64 dynamic metadata and reports the checked `DT_SONAME` string for each input. It reuses the existing checked ELF header, program-header, `PT_DYNAMIC`, `DT_STRTAB`, `DT_STRSZ`, virtual-to-file mapping, unique-tag, and bounded dynamic-string machinery rather than trusting section headers or raw offsets.

A valid image with no `DT_SONAME` reports `DT_SONAME: <none>`; the tool does not infer a SONAME from the filename. A present tag must be unique and its string offset must lie within the declared dynamic string table and reach a NUL terminator before `DT_STRSZ` ends. Malformed metadata fails closed before stdout is emitted.

GNU binutils-backed regression coverage emits shared objects with and without `ld -soname`, cross-checks the resulting metadata with `readelf -dW`, and corrupts the on-disk `DT_SONAME` offset to prove out-of-range dynamic strings are rejected atomically.

This is an inspection/validation slice only. It does not yet use SONAMEs for dependency deduplication, replacement, cache lookup, symbol-version matching, or relocation application.
