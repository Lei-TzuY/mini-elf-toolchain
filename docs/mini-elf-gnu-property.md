# mini-elf-gnu-property

`mini-elf-gnu-property` inspects the ELF64 x86-64 `PT_GNU_PROPERTY` program-header segment and decodes the bounded GNU x86 feature policy carried by `GNU_PROPERTY_X86_FEATURE_1_AND`.

The tool validates the program-header and segment file ranges with checked arithmetic, requires each `PT_GNU_PROPERTY` payload to be an `NT_GNU_PROPERTY_TYPE_0` note owned by `GNU`, walks descriptor properties with the ELF64 8-byte property alignment, validates every property header/data/padding range, rejects duplicate `GNU_PROPERTY_X86_FEATURE_1_AND` entries, and requires that feature property to contain exactly one 32-bit bitmask.

Recognized x86 feature bits are:

- `IBT` (`GNU_PROPERTY_X86_FEATURE_1_IBT`)
- `SHSTK` (`GNU_PROPERTY_X86_FEATURE_1_SHSTK`)

Unknown bits are preserved numerically rather than silently discarded.

```text
mini-elf-gnu-property <input>...
```

Multiple inputs are fully validated before stdout is emitted, so a malformed later input cannot leave partial inspection output behind.

This is an inspection/validation slice only. It does not mutate ELF files, enforce CET at runtime, build process images, or implement the wider GNU property namespace.
