# `mini-elf-eh-frame-lsda`

`mini-elf-eh-frame-lsda` adds one bounded GNU `.eh_frame` exception-metadata slice on top of the checked `.eh_frame_hdr` / indexed FDE / CIE path: version-1 `zPLR` CIEs with direct PC-relative signed-32 personality, LSDA, and FDE encodings.

```sh
mini-elf-eh-frame-lsda ./app
mini-elf-eh-frame-lsda ./app ./libexample.so
```

The tool accepts ELF64 x86-64 images with the common GNU `.eh_frame_hdr` tuple (`0x1b/0x03/0x3b`). Each indexed FDE is mapped through checked file-backed `PT_LOAD` bytes, its preceding CIE back-reference is validated, and the CIE must use augmentation string `zPLR`.

For this slice the CIE augmentation payload is exact: `P=DW_EH_PE_pcrel | DW_EH_PE_sdata4` (`0x1b`), one signed 32-bit personality displacement, `L=DW_EH_PE_pcrel | DW_EH_PE_sdata4` (`0x1b`), then `R=DW_EH_PE_pcrel | DW_EH_PE_sdata4` (`0x1b`). The personality target must resolve into executable file-backed `PT_LOAD` data. Because `R` fixes the FDE initial-location representation to four bytes and the range representation to four bytes, the FDE augmentation length is then decoded immediately after those fixed fields and must contain exactly one four-byte LSDA pointer.

The LSDA displacement is relative to its encoded FDE field. Signed pointer arithmetic is checked for overflow/underflow, and the decoded LSDA address must resolve into file-backed `PT_LOAD` bytes. The LSDA itself is deliberately treated as opaque data: this slice does not parse call-site tables, action tables, type tables, landing pads, or language-specific exception semantics.

Program-header file, memory, and file-backed virtual ranges are checked before use; CIE/FDE records may not cross a file-backed load boundary. Unsupported CIE/LSDA/FDE encodings, malformed or oversized augmentation lengths, truncated records, pointer arithmetic failure, unmapped LSDA targets, and malformed later inputs fail closed. Multiple inputs are fully validated before stdout is emitted.

Focused regressions build a real GNU `as` / `ld -shared --eh-frame-hdr` fixture using `.cfi_personality 0x1b, personality` plus `.cfi_lsda 0x1b, lsda`. GNU `readelf -wf` supplies differential evidence for the `zPLR` CIE, while `readelf -sW` supplies the resolved personality and LSDA symbol addresses. Malformed coverage changes the LSDA encoding, forces signed-pointer underflow, redirects the LSDA pointer outside all file-backed loads, corrupts the FDE augmentation length, and verifies later-input stdout atomicity.

Indirect encodings such as `0x9b`, `zLR` without a personality field, other DWARF pointer representations, CFI instruction interpretation, LSDA parsing, and stack unwinding remain outside this bounded slice.
