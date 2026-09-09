# `mini-elf-eh-frame-personality`

`mini-elf-eh-frame-personality` adds one bounded GNU `.eh_frame` exception-metadata slice on top of the checked `.eh_frame_hdr` / FDE / CIE path: version-1 `zPR` CIE personality augmentation with direct PC-relative signed-32 encoding.

```sh
mini-elf-eh-frame-personality ./app
mini-elf-eh-frame-personality ./app ./libexample.so
```

The tool accepts ELF64 x86-64 images with the common GNU `.eh_frame_hdr` tuple (`0x1b/0x03/0x3b`). Every indexed FDE is mapped through a checked file-backed `PT_LOAD`, its preceding CIE back-reference is validated, and the CIE must use augmentation string `zPR`.

For this slice the augmentation payload is deliberately exact: six bytes containing `P=DW_EH_PE_pcrel | DW_EH_PE_sdata4` (`0x1b`), the signed 32-bit personality displacement, then `R=DW_EH_PE_pcrel | DW_EH_PE_sdata4` (`0x1b`). The personality displacement is relative to the encoded pointer field itself. Address arithmetic is checked, and the decoded personality target must reside in executable file-backed `PT_LOAD` bytes. Program-header file, memory, and file-backed virtual ranges are checked before use; CIE/FDE records may not cross a file-backed load boundary.

Malformed CIE/FDE records, unsupported augmentation strings or encodings, truncated/oversized augmentation payloads, pointer overflow/underflow, and personality targets outside executable file-backed mappings fail closed. Multiple inputs are fully validated before stdout is emitted.

Focused regressions build a real GNU `as` / `ld -shared --eh-frame-hdr` fixture using `.cfi_personality 0x1b, personality`. GNU `readelf -wf` supplies differential evidence for the `zPR` CIE while `readelf -sW` supplies the resolved personality symbol address. Malformed coverage changes the personality encoding, forces signed-pointer underflow, redirects the pointer into non-executable unwind data, corrupts the payload length, and verifies later-input stdout atomicity.

This slice intentionally does not support indirect personality encodings such as `0x9b`, `L`/LSDA augmentation, FDE augmentation payloads, CFI instruction interpretation, language-specific exception tables, or stack unwinding.
