# Bounded linker-script image base

The static linker accepts a deliberately small first linker-script slice through `-T <script>` or `--script <script>`.

The supported grammar is exactly one location-counter assignment inside a `SECTIONS` block:

```ld
SECTIONS { . = 0x800000; }
```

Whitespace and newlines may vary, and the address may be hexadecimal or decimal. The address is parsed as a checked unsigned 64-bit value and is fed into the same permission-aware layout and ELF emission pipeline as `--image-base`.

`--image-base` and `-T`/`--script` are mutually exclusive, and multiple script options are rejected. Malformed scripts, unsupported trailing commands, non-UTF-8 content, unreadable files, and overflowing addresses fail before output emission.

This milestone intentionally does **not** implement named output-section placement, symbol assignments, `ENTRY`, `MEMORY`, `PHDRS`, `INCLUDE`, wildcard input-section matching, expressions, or dynamic-linking script semantics. Those require separate executable vertical slices rather than silently accepting syntax that this linker cannot honor.
