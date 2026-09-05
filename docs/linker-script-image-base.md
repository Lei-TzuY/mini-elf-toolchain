# Bounded linker-script image base

The static linker accepts a deliberately small linker-script slice through `-T <script>` or `--script <script>`.

Two executable forms are supported. The original location-counter form is:

```ld
SECTIONS { . = 0x800000; }
```

A bounded GNU-compatible `.text` output-section placement form is also accepted:

```ld
SECTIONS { .text 0x900000 : { *(.text) } }
```

For the current static layout model, the explicit `.text` address selects the image base and the exact `*(.text)` body states that this slice is placing the executable text input section at that address. Both forms therefore feed the checked address into the same permission-aware layout and ELF emission pipeline as `--image-base`.

Whitespace and newlines may vary, and addresses may be hexadecimal or decimal. Addresses are parsed as checked unsigned 64-bit values. The `.text` form deliberately accepts only the exact output-section name `.text` and the exact input-section selector `*(.text)`; other output sections, additional selectors, additional output sections, and arbitrary wildcard patterns are rejected rather than silently ignored.

`--image-base` and `-T`/`--script` are mutually exclusive, and multiple script options are rejected. Malformed scripts, unsupported trailing commands, non-UTF-8 content, unreadable files, and overflowing addresses fail before output emission.

This milestone intentionally does **not** implement general named output-section placement, multiple output sections, symbol assignments, `ENTRY`, `MEMORY`, `PHDRS`, `INCLUDE`, general wildcard matching, expressions, or dynamic-linking script semantics. Those require separate executable vertical slices rather than accepting syntax the linker cannot yet honor.
