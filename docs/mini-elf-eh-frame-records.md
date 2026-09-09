# `mini-elf-eh-frame-records`

`mini-elf-eh-frame-records` is a bounded ELF64 x86-64 dynamic-loader/unwind-metadata inspector that dereferences the FDE addresses indexed by a GNU `.eh_frame_hdr` binary-search table and validates the immediate `.eh_frame` record structure.

```sh
mini-elf-eh-frame-records ./app
mini-elf-eh-frame-records ./app ./libexample.so
```

The tool requires the common GNU x86-64 `.eh_frame_hdr` encoding tuple produced by `ld --eh-frame-hdr`: PC-relative signed-32 `.eh_frame` pointer encoding (`0x1b`), unsigned-32 FDE count (`0x03`), and data-relative signed-32 search-table encoding (`0x3b`). The complete header/table envelope is checked before traversal.

For every indexed FDE address, the inspector maps the virtual address through a file-backed `PT_LOAD`, reads the 32-bit `.eh_frame` record length, and checks the complete record envelope with checked arithmetic. Zero-length terminators, lengths smaller than the mandatory 4-byte id/pointer field, records crossing their file-backed load mapping, and the `0xffffffff` DWARF64 length marker are rejected. DWARF64 records remain intentionally outside this bounded slice rather than being partially interpreted.

The FDE's 32-bit CIE-pointer back-reference is decoded from the address of its own field using checked subtraction. The referenced record must precede the FDE, map through a file-backed `PT_LOAD`, have a valid bounded 32-bit record envelope, contain room for a CIE id plus version byte, and carry the `.eh_frame` CIE id value `0`. This establishes that every search-table FDE points at an immediate structurally valid CIE/FDE pair before any future call-frame-instruction decoding relies on it.

All inputs are validated before stdout is emitted, preserving atomic output for malformed later inputs. The focused regression suite builds real GNU `as`/`ld --eh-frame-hdr` shared objects, differentially compares indexed FDE virtual addresses with GNU `readelf -wf`, and covers unsupported DWARF64 markers, oversized record envelopes, CIE-pointer underflow, non-CIE targets, and multi-input atomicity.

This slice deliberately does not parse augmentation strings, pointer encodings declared by the CIE, FDE initial-location/range payloads, DWARF call-frame instructions, LSDA data, or perform stack unwinding. Those require subsequent independently executable slices.