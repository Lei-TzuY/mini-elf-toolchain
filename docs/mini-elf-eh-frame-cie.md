# `mini-elf-eh-frame-cie`

`mini-elf-eh-frame-cie` is a bounded ELF64 x86-64 unwind-metadata inspector that follows GNU `.eh_frame_hdr` binary-search entries to their indexed FDEs, resolves each FDE's CIE back-reference, and validates the first CIE metadata fields before any later augmentation-payload or CFI decoding relies on them.

```sh
mini-elf-eh-frame-cie ./app
mini-elf-eh-frame-cie ./app ./libexample.so
```

The tool requires the common GNU x86-64 `.eh_frame_hdr` encoding tuple emitted by `ld --eh-frame-hdr`: PC-relative signed-32 `.eh_frame` pointer encoding (`0x1b`), unsigned-32 FDE count (`0x03`), and data-relative signed-32 search-table encoding (`0x3b`). Program-header ranges, the complete header/table envelope, FDE record envelopes, and CIE back-references are checked with overflow-safe arithmetic and file-backed `PT_LOAD` containment.

For every indexed FDE, the referenced CIE must be a bounded 32-bit `.eh_frame` CIE record with id `0`, version `1`, and a NUL-terminated augmentation string fully contained inside that CIE record. The augmentation bytes must be valid UTF-8 before they are rendered. Unsupported CIE versions, truncated records, malformed back-references, and unterminated augmentation strings fail closed.

All inputs are validated before stdout is emitted, preserving atomic output for malformed later inputs. Focused regressions build real GNU `as`/`ld --eh-frame-hdr` shared objects, compare the decoded augmentation string with GNU `readelf -wf`, and cover unsupported CIE versions, unterminated augmentation strings, and multi-input atomicity.

This slice deliberately stops before parsing augmentation payloads such as `zR`, the CIE-declared FDE pointer encoding, initial-location/range fields, DWARF call-frame instructions, LSDA data, or performing stack unwinding. Those remain separate executable vertical slices.
