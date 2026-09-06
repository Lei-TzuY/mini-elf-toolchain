# Bounded `R_X86_64_GOTPLT64` static GOT-offset relocation

This checkpoint adds x86-64 relocation type 30, `R_X86_64_GOTPLT64`, to the existing deterministic synthetic-GOT static-link path.

Within the current non-preemptible `ET_EXEC` scope, the linker evaluates the psABI large-model formula:

```text
G + A
```

`G` is the selected symbol's offset to its GOT entry from the linker's synthetic GOT base. The addend is applied with checked unsigned 64-bit conversion and the relocation target must contain a full 8-byte field. This is intentionally the same value class as the existing bounded `R_X86_64_GOT64` path; `GOTPLT64` additionally carries the psABI implication that a corresponding PLT entry may exist in a dynamic-linking implementation.

The current linker does not build a PLT. For its static, non-preemptible executable model, `R_X86_64_GOTPLT64` therefore reuses the deterministic global/weak GOT collection path. GNU differential coverage reconstructs the selected GOT entry from a `GOTPC64` base plus the `GOTPLT64` offset, so both the mini linker and GNU `ld --no-relax` are checked by executing their outputs without assuming identical physical `.got`/`.got.plt` layout.

This does not introduce PLT construction, symbol interposition, shared objects, dynamic relocations, TLS, or a dynamic loader.
