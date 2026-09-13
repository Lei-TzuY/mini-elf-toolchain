# `mini-elf-needed-preload-token-resolve`

`mini-elf-needed-preload-token-resolve [--secure] <symbol> <root-et-dyn> <fallback-library-dir>` extends the bounded preload resolver with checked dynamic-token expansion for explicit `LD_PRELOAD` pathnames.

The supported tokenized pathname form is deliberately narrow and deterministic: the entry must be anchored by `$ORIGIN` or `${ORIGIN}`. `$LIB` / `${LIB}` and `$PLATFORM` / `${PLATFORM}` are accepted only as whole path components beneath that origin and model to `lib64` and `x86_64` respectively. The origin is the directory containing the modeled root image. Expanded entries then pass through the existing preload resolver, preserving root-before-preload lookup, declared preload order, bare-name search, dependency resolution, malformed-ELF validation, and stdout atomicity.

Traversal and ambiguous token placement fail closed. Empty, `.` or `..` components, a tokenized entry not anchored at `$ORIGIN`, and embedded `$` syntax outside the supported component forms are rejected before symbol-resolution output is committed. Non-token preload entries retain the existing pathname/bare-name behavior.

`--secure` intentionally delegates without parsing or expanding `LD_PRELOAD`, matching the existing bounded secure-mode rule that ambient preload state is suppressed entirely.

Focused GNU-binutils-backed regressions construct real ELF64 x86-64 shared objects with `as` and `ld`, validate their dynamic metadata with `readelf`, and cover `$ORIGIN/$LIB/$PLATFORM` expansion, declared ordering alongside an ordinary preload pathname, malformed traversal/unanchored tokens, and secure suppression.

This slice does not attempt arbitrary token substitution inside basenames, `/etc/ld.so.preload`, audit namespaces, ld.so.cache/hwcap selection, credential-derived `AT_SECURE`, or the secure-mode set-user-ID preload exception.
