# Bounded `R_X86_64_PLTOFF64` static semantics

The ELF64 x86-64 static linker accepts relocation type 31, `R_X86_64_PLTOFF64`, inside the current non-preemptible `ET_EXEC` scope.

The AMD64 ABI formula is `L + A - GOT`, where `L` is the PLT entry address. This linker does not emit dynamic symbols or a PLT; every resolved definition is non-preemptible. For this bounded static case, `L` therefore resolves directly to the final symbol address and `GOT` is the deterministic synthetic GOT base already used by the static GOT relocation family.

The result is validated as a signed 64-bit value and written through the existing checked 8-byte relocation target path. GNU `as`/`ld`/`readelf` differential coverage exercises the same relocation in a static executable and Linux CI executes both outputs.

This slice does not add PLT entries, `.got.plt`, symbol interposition, shared objects, dynamic relocations, TLS, or a runtime loader. Those require separate executable vertical slices rather than being implied by support for this non-preemptible relocation form.
