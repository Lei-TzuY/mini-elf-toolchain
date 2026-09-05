# Bounded linker-script comments

The current linker-script subset accepts GNU-compatible C-style block comments (`/* ... */`) as whitespace anywhere that the bounded grammar already accepts whitespace. This includes around `ENTRY(symbol)`, the location-counter assignment, and the supported `.text` selectors.

Example:

```ld
/* static image */
ENTRY(/* entry */ _start)
SECTIONS {
  /* image base */ . = 0x900000;
  .text : { *(/* family */ .text .text.*) }
}
```

Comments do not expand the grammar. The parser still only accepts the existing bounded `ENTRY`, location-counter, `.text`, and `.text .text.*` forms. Nested comments are not treated specially, and an unterminated block comment is rejected before output emission.
