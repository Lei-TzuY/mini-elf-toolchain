# `mini-elf-dynamic-hash-resolve`

`mini-elf-dynamic-hash-resolve <symbol> <input>...` performs bounded ordered external-definition resolution across explicit ELF64 x86-64 `ET_DYN` inputs even when the lookup scope mixes GNU `DT_GNU_HASH` and legacy SysV `DT_HASH` objects.

Each input is examined in command-line order. If `DT_GNU_HASH` is present, the existing checked GNU-hash external lookup path is authoritative for that object. If GNU hash is absent, the resolver falls back to the existing checked SysV-hash external lookup path. A malformed present GNU hash is an error and never silently falls back to SysV, preserving fail-closed validation. Eligible external definitions retain the existing defined, non-local, non-hidden/non-internal requirements.

The first eligible definition wins. If no input provides one, the tool reports `not-found`. Inputs are fully processed before stdout is emitted, so a malformed earlier object cannot leave partial resolution output.

This is deliberately a bounded loader-resolution slice. It does not discover `DT_NEEDED` dependencies, construct ELF loader scope automatically, apply symbol version rules, implement interposition policy, evaluate IFUNC resolvers, or apply relocations.
