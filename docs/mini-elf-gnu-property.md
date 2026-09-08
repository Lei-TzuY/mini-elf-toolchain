# mini-elf-gnu-property

`mini-elf-gnu-property` inspects the ELF64 x86-64 `PT_GNU_PROPERTY` program-header segment and decodes a bounded GNU x86 policy subset carried by `GNU_PROPERTY_X86_FEATURE_1_AND`, `GNU_PROPERTY_X86_ISA_1_NEEDED`, and `GNU_PROPERTY_X86_ISA_1_USED`.

The tool validates the program-header and segment file ranges with checked arithmetic, requires each `PT_GNU_PROPERTY` payload to be an `NT_GNU_PROPERTY_TYPE_0` note owned by `GNU`, walks descriptor properties with the ELF64 8-byte property alignment, validates every property header/data/padding range, rejects duplicate recognized entries, and requires each recognized property to contain exactly one 32-bit bitmask.

Recognized x86 feature bits are:

- `IBT` (`GNU_PROPERTY_X86_FEATURE_1_IBT`)
- `SHSTK` (`GNU_PROPERTY_X86_FEATURE_1_SHSTK`)

Recognized x86 ISA-needed and ISA-used levels are:

- `x86-64-baseline`
- `x86-64-v2`
- `x86-64-v3`
- `x86-64-v4`

`GNU_PROPERTY_X86_ISA_1_NEEDED` describes ISA levels that must be available, while `GNU_PROPERTY_X86_ISA_1_USED` records ISA levels used by the program whose hardware support is optional according to the GNU property ABI. Unknown bits in each recognized mask are preserved numerically rather than silently discarded.

```text
mini-elf-gnu-property <input>...
```

Multiple inputs are fully validated before stdout is emitted, so a malformed later input cannot leave partial inspection output behind.

This is an inspection/validation slice only. It does not mutate ELF files, probe the host CPU, enforce CET or ISA requirements at runtime, build process images, or implement the wider GNU property namespace.