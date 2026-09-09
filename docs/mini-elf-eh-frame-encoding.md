# `mini-elf-eh-frame-encoding`

`mini-elf-eh-frame-encoding` advances the checked GNU `.eh_frame` path by validating the CIE augmentation payload that declares how indexed FDE addresses are encoded and by decoding the corresponding bounded FDE code ranges.

```sh
mini-elf-eh-frame-encoding ./app
mini-elf-eh-frame-encoding ./app ./libexample.so
```

The tool requires the common GNU x86-64 `.eh_frame_hdr` tuple (`0x1b/0x03/0x3b`), follows each binary-search entry to its file-backed FDE and preceding CIE, and accepts version-1 CIEs with exactly the `zR` augmentation used by GNU `ld --eh-frame-hdr` fixtures. It decodes the CIE code-alignment ULEB128, data-alignment SLEB128, return-register ULEB128, and `z` augmentation-length ULEB128 with bounded checked parsing. The declared augmentation payload must remain inside the CIE record and contain exactly one `R` byte.

For this vertical slice the accepted CIE-declared FDE pointer encoding is `DW_EH_PE_pcrel | DW_EH_PE_sdata4` (`0x1b`). The FDE initial-location field is decoded as a signed 32-bit PC-relative displacement from the field's own virtual address. The following address-range field uses the encoding's signed 32-bit data format without the PC-relative application; negative ranges are rejected and the resulting `initial + range` code-range end uses checked `u64` arithmetic. The fixed FDE fields must remain inside the already-validated file-backed FDE record envelope.

Unsupported augmentation directives, unsupported FDE encodings, malformed or overlong LEB128 fields, truncated payloads or FDE fixed fields, PC-relative underflow/overflow, negative address ranges, record/file-range overflow, and non-file-backed FDE/CIE references fail closed. Multiple inputs are fully validated before stdout is emitted.

Focused regressions build real GNU `as`/`ld -shared --eh-frame-hdr` objects and compare `zR`, augmentation byte `1b`, and decoded FDE `pc=start..end` ranges with GNU `readelf -wf`. Malformed tests cover an unsupported FDE encoding, an augmentation length that exceeds the CIE envelope, an FDE initial-location underflow, a truncated FDE fixed-field envelope, and later-input stdout atomicity.

This slice does not yet validate decoded code ranges against executable `PT_LOAD` mappings, parse LSDA/personality augmentation directives, interpret call-frame instructions, or perform stack unwinding. Those remain separate bounded capabilities.
