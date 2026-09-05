# Bounded linker-script subset

The static linker deliberately supports only a small, executable subset of GNU linker-script syntax. Unsupported directives are rejected rather than accepted without effect.

Accepted forms are:

```ld
SECTIONS { . = 0x800000; }
```

```ld
SECTIONS { .text 0x800000 : { *(.text) } }
```

```ld
SECTIONS { . = 0x800000; .text : { *(.text) } }
```

The `.text` output-section body also accepts two bounded GNU text-family selectors:

```ld
SECTIONS { . = 0x800000; .text : { *(.text .text.*) } }
SECTIONS { . = 0x800000; .text : { *(.text*) } }
```

Both forms admit the ordinary `.text` input section plus `.text.*` function/fragment sections used by common assembler/compiler workflows. The compact `*(.text*)` spelling is handled as this exact bounded family, not as a general glob engine. Wildcard-only `*(.text.*)`, doubled wildcards such as `*(.text**)`, reordered families, arbitrary wildcard patterns, and other section families remain rejected rather than being accepted without corresponding layout semantics.

An optional entry directive may appear before the `SECTIONS` block:

```ld
ENTRY(custom_entry)
SECTIONS { . = 0x800000; }
```

`ENTRY(symbol)` selects the resolved global/weak symbol used as the ELF executable entry point. An explicit CLI `--entry <symbol>` takes precedence over the script directive, matching GNU `ld -e` override behavior. The entry directive accepts exactly one non-empty symbol token; malformed or repeated directives are rejected before output emission.

The address is a checked unsigned 64-bit hexadecimal or decimal value and feeds the existing static image layout. The `.text` placement forms remain bounded aliases for selecting the current static image base; they are not a general output-section layout engine. The sequenced form applies the location-counter assignment first and then requires exactly one `.text` output section at that current address, using `*(.text)`, the explicit `*(.text .text.*)` family, or compact `*(.text*)`.

General output-section placement, symbol assignments, `PROVIDE`, expressions, `MEMORY`, `PHDRS`, general wildcard matching, orphan-section policy, `INCLUDE`, multiple script files, shared-object semantics, and dynamic-link directives remain out of scope until implemented as separate vertical slices.
