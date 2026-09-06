# Bounded `R_X86_64_GOTPC32` support

The ELF64 x86-64 static linker accepts relocation type 26 (`R_X86_64_GOTPC32`) as a bounded static-GOT base relocation.

For the current synthetic GOT model, the relocation is evaluated as the ABI PC-relative form `GOT + A - P`, where `GOT` is the deterministic base address of the synthetic writable GOT, `A` is the signed RELA addend, and `P` is the relocation place. The result must fit a signed 32-bit field and the relocation target range is checked before writing.

`R_X86_64_GOTPC32` participates in the existing static-GOT symbol collection so a referenced global or weak symbol establishes the synthetic GOT region using the same deterministic ordering and validation as the already-supported GOT32/GOT64/GOTPCREL families. The relocation itself uses the GOT base, not the selected symbol's entry address.

This slice intentionally does not add PLT/GOTPLT semantics, dynamic linking, TLS relocations, GOTOFF64, or broader GOT-base relocation families. GNU `as`, `ld`, and `readelf` are used in integration tests as a compatibility oracle, and the mini-linker output is executed on Linux to validate the relocated value against the synthetic GOT entry address.
