# Bounded `R_X86_64_GOTPC64` static GOT-base relocation

This checkpoint extends the existing deterministic synthetic-GOT path with x86-64 relocation type 29, `R_X86_64_GOTPC64`.

The supported static-link semantics are the ABI formula:

```text
GOT + A - P
```

where `GOT` is the synthetic GOT base, `A` is the signed RELA addend, and `P` is the relocation place. The result is checked for signed 64-bit range before an 8-byte little-endian write, and relocation target bounds remain checked before mutation.

`R_X86_64_GOTPC64` participates in the same bounded synthetic-GOT construction used by the existing GOTPC32/GOT/GOTPCREL families. This milestone does not add PLT/GOTPLT construction, TLS, shared objects, dynamic relocation processing, or a dynamic loader.
