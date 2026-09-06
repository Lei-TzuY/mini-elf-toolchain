# Bounded `R_X86_64_GOTPLT64` static GOT-entry-address relocation

This checkpoint adds x86-64 relocation type 30, `R_X86_64_GOTPLT64`, to the existing deterministic synthetic-GOT static-link path.

Within the current non-preemptible `ET_EXEC` scope, the linker evaluates the psABI formula:

```text
G + GOT + A
```

`G` is the selected symbol's synthetic GOT-entry offset, `GOT` is the synthetic GOT base, and their sum is therefore the absolute address of that GOT entry. The addend is applied with checked unsigned 64-bit conversion and the relocation target must contain a full 8-byte field.

`R_X86_64_GOTPLT64` references allocate entries through the same deterministic global/weak GOT collection path as the other supported static GOT relocations. GNU assembler/linker differential coverage checks the real relocation spelling and executable result.

This does not introduce a PLT, symbol interposition, shared objects, dynamic relocations, TLS, or a dynamic loader.
