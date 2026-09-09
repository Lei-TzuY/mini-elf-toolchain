# `mini-elf-eh-frame-exec`

`mini-elf-eh-frame-exec` extends the checked GNU `.eh_frame` path from decoding FDE code ranges to validating that each decoded half-open code range is actually backed by executable image bytes.

```sh
mini-elf-eh-frame-exec ./app
mini-elf-eh-frame-exec ./app ./libexample.so
```

The tool accepts ELF64 x86-64 images with the common GNU `.eh_frame_hdr` encoding tuple (`0x1b/0x03/0x3b`). For every indexed FDE it follows the checked file-backed mapping, validates the preceding version-1 `zR` CIE and its `DW_EH_PE_pcrel | DW_EH_PE_sdata4` (`0x1b`) FDE encoding, decodes the PC-relative signed-32 initial location and non-negative signed-32 address range, and checks `initial + range` with overflow-safe arithmetic.

The resulting half-open range `[initial, end)` must be fully contained in one `PF_X` `PT_LOAD` file-backed virtual range. This is intentionally stronger than checking only the initial PC: an FDE whose starting address is executable but whose declared range escapes into a non-executable or zero-fill region fails closed. Program-header file, memory, and file-backed virtual ranges are checked before use.

Malformed CIE/FDE records, unsupported encodings, truncated fixed fields, pointer/range arithmetic overflow, non-file-backed unwind records, and code ranges that escape executable file-backed mappings are rejected. Multiple inputs are fully validated before stdout is emitted.

Focused regressions build a real GNU `as` / `ld -shared --eh-frame-hdr` fixture and compare decoded code ranges with GNU `readelf -wf`. Malformed coverage expands an FDE range beyond its executable load, forces a `PT_LOAD` virtual-range overflow, and verifies later-input stdout atomicity.

This slice does not parse LSDA/personality augmentations, interpret CFI instructions, build an unwinder, or broaden the accepted CIE FDE encoding beyond the current GNU x86-64 `0x1b` path.
