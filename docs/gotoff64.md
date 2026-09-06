# Bounded `R_X86_64_GOTOFF64` support

This checkpoint adds x86-64 relocation type 25, `R_X86_64_GOTOFF64`, to the deterministic static-GOT path.

The relocation is evaluated as `S + A - GOT`, where `S` is the resolved symbol address, `A` is the RELA addend, and `GOT` is the base of the synthetic writable GOT region. The result is checked as a signed 64-bit value and written to an 8-byte relocation field. A GOTOFF64 reference participates in synthetic-GOT collection so the bounded static linker has a deterministic GOT base even when no other GOT-family relocation is present.

Arithmetic overflow and relocation target bounds are rejected before mutating the final section image. GNU `as`, `ld --no-relax`, and `readelf` differential coverage verifies that genuine `R_X86_64_GOTOFF64` input objects link into executable `ET_EXEC` outputs. PLT, TLS, shared-object, and dynamic-loader semantics remain outside this slice.
