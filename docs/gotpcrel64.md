# Bounded `R_X86_64_GOTPCREL64` static GOT-entry relocation

This checkpoint extends the deterministic synthetic static-GOT path with x86-64 relocation type 28, `R_X86_64_GOTPCREL64`.

The supported static-link semantics are the ABI GOT-entry PC-relative formula:

```text
GOT-entry + A - P
```

The result is checked as a signed 64-bit value and written to an 8-byte relocation field. Referenced global/weak symbols continue to allocate deterministic 8-byte synthetic GOT entries through the same validated path used by `R_X86_64_GOTPCREL`; target bounds and arithmetic overflow remain checked before mutation.

GNU differential coverage requires GNU `as` to emit `R_X86_64_GOTPCREL64` from a `.quad symbol@GOTPCREL`, then links the same object with this linker and GNU `ld --no-relax`, verifies `ET_EXEC` with `readelf`, and executes both outputs on Linux.

This slice does not add PLT construction, TLS, shared objects, dynamic loading, or instruction relaxation.
