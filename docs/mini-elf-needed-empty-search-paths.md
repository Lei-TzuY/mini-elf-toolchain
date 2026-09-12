# Empty `DT_RUNPATH` / `DT_RPATH` components

`mini-elf-needed-absolute-runpath-resolve` treats an empty colon-separated component in checked `DT_RUNPATH` or `DT_RPATH` metadata as the process current working directory. This covers wholly empty path values as well as leading, trailing, and repeated `:` components while preserving component order.

The behavior composes with the existing bounded loader model: `DT_RUNPATH` remains local to the image that declares it, legacy `DT_RPATH` remains inheritable by descendants, explicit loader-path directories retain their existing precedence, and SONAME identity plus breadth-first dependency scope are unchanged. Non-empty ordinary relative paths are still required to be normalized and are resolved against process cwd; `$ORIGIN`, `$LIB`, and `$PLATFORM` continue through the checked token-expansion path.

Focused GNU binutils-backed integration constructs real shared objects with `ld`, confirms the emitted dynamic tags with `readelf -dW`, verifies that a leading empty RUNPATH component searches cwd before a later directory, and verifies that a trailing empty legacy RPATH component is inherited by a transitive dependency.
