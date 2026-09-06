# GNU archive-group aliases

The static-link CLI accepts GNU ld's short archive-group marker aliases `-(` and `-)` in addition to `--start-group` and `--end-group`.

```sh
mini-elf-toolchain link -o app start.o -( liba.a libb.a -)
```

The aliases are canonicalized into the existing bounded archive-group engine before input loading. They therefore preserve the same left-to-right first pass, bounded lazy-archive rescanning, whole-archive state handling, and balanced nested-group normalization as the long GNU forms.

Mixed long/short markers are allowed. Unbalanced short markers are canonicalized to the existing long-form diagnostics rather than being interpreted as filenames. This slice does not change archive extraction policy outside explicit groups and does not add shared-library behavior.
