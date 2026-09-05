use core::fmt;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_IMAGE_BASE: u64 = 0x400000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageBaseArguments {
    pub arguments: Vec<OsString>,
    pub image_base: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageBaseArgumentError {
    MissingValue,
    EmptyValue,
    DuplicateOption,
    NonUtf8Value,
    InvalidValue { value: String },
    EmptyEntrySymbol,
    MissingScriptPath,
    EmptyScriptPath,
    DuplicateScriptOption,
    ConflictingSources,
    ReadScript { path: PathBuf, message: String },
    NonUtf8Script { path: PathBuf },
    InvalidScript { path: PathBuf, message: String },
}

impl fmt::Display for ImageBaseArgumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue => write!(f, "missing address after --image-base"),
            Self::EmptyValue => write!(f, "image base cannot be empty"),
            Self::DuplicateOption => write!(f, "duplicate --image-base option"),
            Self::NonUtf8Value => write!(f, "image base must be UTF-8 hexadecimal or decimal"),
            Self::InvalidValue { value } => write!(
                f,
                "invalid image base '{value}'; expected an unsigned 64-bit hexadecimal or decimal address"
            ),
            Self::EmptyEntrySymbol => write!(f, "entry symbol cannot be empty"),
            Self::MissingScriptPath => write!(f, "missing linker script path after -T/--script"),
            Self::EmptyScriptPath => write!(f, "linker script path cannot be empty"),
            Self::DuplicateScriptOption => write!(f, "duplicate -T/--script option"),
            Self::ConflictingSources => write!(
                f,
                "cannot combine --image-base with -T/--script image-base selection"
            ),
            Self::ReadScript { path, message } => {
                write!(f, "cannot read linker script '{}': {message}", path.display())
            }
            Self::NonUtf8Script { path } => write!(
                f,
                "linker script '{}' must contain UTF-8 text",
                path.display()
            ),
            Self::InvalidScript { path, message } => write!(
                f,
                "invalid linker script '{}': {message}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ImageBaseArgumentError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinkerScriptConfig {
    image_base: u64,
    entry_symbol: Option<String>,
}

pub fn extract_image_base_argument(
    arguments: &[OsString],
) -> Result<ImageBaseArguments, ImageBaseArgumentError> {
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut image_base = DEFAULT_IMAGE_BASE;
    let mut image_base_seen = false;
    let mut script_seen = false;
    let mut script_entry_symbol = None;
    let mut index = 0usize;

    while index < arguments.len() {
        if let Some(value) = strip_os_prefix(&arguments[index], "--image-base=") {
            if image_base_seen {
                return Err(ImageBaseArgumentError::DuplicateOption);
            }
            if script_seen {
                return Err(ImageBaseArgumentError::ConflictingSources);
            }
            if value.is_empty() {
                return Err(ImageBaseArgumentError::EmptyValue);
            }
            let text = value.to_str().ok_or(ImageBaseArgumentError::NonUtf8Value)?;
            image_base = parse_address(text)?;
            image_base_seen = true;
            index += 1;
            continue;
        }

        if arguments[index] == "--image-base" {
            if image_base_seen {
                return Err(ImageBaseArgumentError::DuplicateOption);
            }
            if script_seen {
                return Err(ImageBaseArgumentError::ConflictingSources);
            }
            let value = arguments
                .get(index + 1)
                .ok_or(ImageBaseArgumentError::MissingValue)?;
            if value.is_empty() {
                return Err(ImageBaseArgumentError::EmptyValue);
            }
            let text = value.to_str().ok_or(ImageBaseArgumentError::NonUtf8Value)?;
            image_base = parse_address(text)?;
            image_base_seen = true;
            index += 2;
            continue;
        }

        if let Some(entry_symbol) = strip_os_prefix(&arguments[index], "--entry=") {
            if entry_symbol.is_empty() {
                return Err(ImageBaseArgumentError::EmptyEntrySymbol);
            }
            remaining.push(OsString::from("--entry"));
            remaining.push(entry_symbol);
            index += 1;
            continue;
        }

        if let Some(path) = arguments[index]
            .to_str()
            .and_then(|argument| argument.strip_prefix("--script="))
        {
            if script_seen {
                return Err(ImageBaseArgumentError::DuplicateScriptOption);
            }
            if image_base_seen {
                return Err(ImageBaseArgumentError::ConflictingSources);
            }
            if path.is_empty() {
                return Err(ImageBaseArgumentError::EmptyScriptPath);
            }
            let config = parse_linker_script_file(Path::new(path))?;
            image_base = config.image_base;
            script_entry_symbol = config.entry_symbol;
            script_seen = true;
            index += 1;
            continue;
        }

        if let Some(path) = arguments[index]
            .to_str()
            .and_then(|argument| argument.strip_prefix("-T"))
            .filter(|path| !path.is_empty())
        {
            if script_seen {
                return Err(ImageBaseArgumentError::DuplicateScriptOption);
            }
            if image_base_seen {
                return Err(ImageBaseArgumentError::ConflictingSources);
            }
            let config = parse_linker_script_file(Path::new(path))?;
            image_base = config.image_base;
            script_entry_symbol = config.entry_symbol;
            script_seen = true;
            index += 1;
            continue;
        }

        if arguments[index] == "-T" || arguments[index] == "--script" {
            if script_seen {
                return Err(ImageBaseArgumentError::DuplicateScriptOption);
            }
            if image_base_seen {
                return Err(ImageBaseArgumentError::ConflictingSources);
            }
            let value = arguments
                .get(index + 1)
                .ok_or(ImageBaseArgumentError::MissingScriptPath)?;
            if value.is_empty() {
                return Err(ImageBaseArgumentError::EmptyScriptPath);
            }
            let config = parse_linker_script_file(Path::new(value))?;
            image_base = config.image_base;
            script_entry_symbol = config.entry_symbol;
            script_seen = true;
            index += 2;
            continue;
        }

        remaining.push(arguments[index].clone());
        index += 1;
    }

    if let Some(entry_symbol) = script_entry_symbol {
        let cli_entry_present = remaining.iter().any(|argument| argument == "--entry");
        if !cli_entry_present {
            remaining.insert(0, OsString::from(entry_symbol));
            remaining.insert(0, OsString::from("--entry"));
        }
    }

    Ok(ImageBaseArguments {
        arguments: remaining,
        image_base,
    })
}

#[cfg(unix)]
fn strip_os_prefix(value: &OsStr, prefix: &str) -> Option<OsString> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let bytes = value.as_bytes();
    let prefix = prefix.as_bytes();
    (bytes.len() >= prefix.len() && bytes.starts_with(prefix))
        .then(|| OsString::from_vec(bytes[prefix.len()..].to_vec()))
}

#[cfg(windows)]
fn strip_os_prefix(value: &OsStr, prefix: &str) -> Option<OsString> {
    let text = value.to_str()?;
    text.strip_prefix(prefix).map(OsString::from)
}

fn parse_linker_script_file(path: &Path) -> Result<LinkerScriptConfig, ImageBaseArgumentError> {
    let bytes = fs::read(path).map_err(|error| ImageBaseArgumentError::ReadScript {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|_| ImageBaseArgumentError::NonUtf8Script {
        path: path.to_path_buf(),
    })?;
    parse_linker_script_config(text).map_err(|message| ImageBaseArgumentError::InvalidScript {
        path: path.to_path_buf(),
        message,
    })
}

#[cfg(test)]
fn parse_linker_script(text: &str) -> Result<u64, String> {
    parse_linker_script_config(text).map(|config| config.image_base)
}

fn parse_linker_script_config(text: &str) -> Result<LinkerScriptConfig, String> {
    let stripped = strip_linker_script_comments(text)?;
    let mut rest = stripped.trim_start();
    let entry_symbol = if rest.starts_with("ENTRY") {
        let (entry_symbol, remaining) = parse_entry_directive(rest)?;
        rest = remaining;
        Some(entry_symbol)
    } else {
        None
    };

    rest = consume_keyword(rest, "SECTIONS")?;
    rest = consume_char(rest, '{')?;

    let trimmed = rest.trim_start();
    let (image_base, remaining) = if trimmed.starts_with(".text") {
        parse_text_output_section(trimmed)?
    } else {
        let (image_base, remaining) = parse_location_counter_assignment(trimmed)?;
        let trimmed_remaining = remaining.trim_start();
        let remaining = if trimmed_remaining.starts_with(".text") {
            parse_text_output_section_at_current_address(trimmed_remaining)?
        } else {
            remaining
        };
        (image_base, remaining)
    };

    rest = consume_char(remaining, '}')?;
    if !rest.trim().is_empty() {
        return Err("unexpected trailing tokens after SECTIONS block".to_owned());
    }
    Ok(LinkerScriptConfig {
        image_base,
        entry_symbol,
    })
}

fn strip_linker_script_comments(text: &str) -> Result<String, String> {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(comment_start) = rest.find("/*") {
        output.push_str(&rest[..comment_start]);
        let after_start = &rest[comment_start + 2..];
        let comment_end = after_start
            .find("*/")
            .ok_or_else(|| "unterminated linker-script comment".to_owned())?;
        output.push(' ');
        rest = &after_start[comment_end + 2..];
    }

    output.push_str(rest);
    Ok(output)
}

fn parse_entry_directive(mut rest: &str) -> Result<(String, &str), String> {
    rest = consume_keyword(rest, "ENTRY")?;
    rest = consume_char(rest, '(')?;
    let trimmed = rest.trim_start();
    let close = trimmed
        .find(')')
        .ok_or_else(|| "expected ')' after ENTRY symbol".to_owned())?;
    let symbol = trimmed[..close].trim();
    if symbol.is_empty() {
        return Err("ENTRY symbol cannot be empty".to_owned());
    }
    if symbol
        .chars()
        .any(|character| character.is_whitespace() || "(){};".contains(character))
    {
        return Err("ENTRY expects exactly one symbol token".to_owned());
    }
    Ok((symbol.to_owned(), &trimmed[close + 1..]))
}

fn parse_location_counter_assignment(mut rest: &str) -> Result<(u64, &str), String> {
    rest = consume_char(rest, '.')?;
    rest = consume_char(rest, '=')?;
    let (image_base, rest) = parse_address_token(rest, &[';', '}'])?;
    let rest = consume_char(rest, ';')?;
    Ok((image_base, rest))
}

fn parse_text_output_section(mut rest: &str) -> Result<(u64, &str), String> {
    rest = consume_literal(rest, ".text")?;
    if rest
        .chars()
        .next()
        .is_some_and(|character| !character.is_whitespace())
    {
        return Err("expected whitespace after '.text' output section name".to_owned());
    }
    let (image_base, next) = parse_address_token(rest, &[':'])?;
    rest = consume_char(next, ':')?;
    rest = parse_text_output_section_body(rest)?;
    Ok((image_base, rest))
}

fn parse_text_output_section_at_current_address(mut rest: &str) -> Result<&str, String> {
    rest = consume_literal(rest, ".text")?;
    rest = consume_char(rest, ':')?;
    parse_text_output_section_body(rest)
}

fn parse_text_output_section_body(mut rest: &str) -> Result<&str, String> {
    rest = consume_char(rest, '{')?;
    rest = consume_char(rest, '*')?;
    rest = consume_char(rest, '(')?;
    rest = consume_literal(rest, ".text")?;

    let trimmed = rest.trim_start();
    if let Some(remaining) = trimmed.strip_prefix('*') {
        rest = remaining;
    } else if let Some(remaining) = trimmed.strip_prefix(".text.*") {
        rest = remaining;
    }

    rest = consume_char(rest, ')')?;
    rest = consume_char(rest, '}')?;
    Ok(rest)
}

fn parse_address_token<'a>(text: &'a str, terminators: &[char]) -> Result<(u64, &'a str), String> {
    let trimmed = text.trim_start();
    let token_len = trimmed
        .find(|character: char| character.is_whitespace() || terminators.contains(&character))
        .unwrap_or(trimmed.len());
    if token_len == 0 {
        return Err("missing location-counter address".to_owned());
    }
    let token = &trimmed[..token_len];
    let image_base = parse_script_address(token)?;
    Ok((image_base, &trimmed[token_len..]))
}

fn consume_keyword<'a>(text: &'a str, keyword: &str) -> Result<&'a str, String> {
    let trimmed = text.trim_start();
    let Some(rest) = trimmed.strip_prefix(keyword) else {
        return Err(format!("expected '{keyword}'"));
    };
    if rest
        .chars()
        .next()
        .is_some_and(|character| !character.is_whitespace() && character != '{' && character != '(')
    {
        return Err(format!("expected '{keyword}'"));
    }
    Ok(rest)
}

fn consume_char(text: &str, expected: char) -> Result<&str, String> {
    let trimmed = text.trim_start();
    trimmed
        .strip_prefix(expected)
        .ok_or_else(|| format!("expected '{expected}'"))
}

fn consume_literal<'a>(text: &'a str, expected: &str) -> Result<&'a str, String> {
    let trimmed = text.trim_start();
    trimmed
        .strip_prefix(expected)
        .ok_or_else(|| format!("expected '{expected}'"))
}

fn parse_script_address(text: &str) -> Result<u64, String> {
    let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() {
            None
        } else {
            u64::from_str_radix(hex, 16).ok()
        }
    } else {
        text.parse::<u64>().ok()
    };
    parsed.ok_or_else(|| {
        format!(
            "invalid location-counter address '{text}'; expected an unsigned 64-bit hexadecimal or decimal value"
        )
    })
}

fn parse_address(text: &str) -> Result<u64, ImageBaseArgumentError> {
    parse_script_address(text).map_err(|_| ImageBaseArgumentError::InvalidValue {
        value: text.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        extract_image_base_argument, parse_linker_script, parse_linker_script_config,
        ImageBaseArgumentError, DEFAULT_IMAGE_BASE,
    };
    use std::ffi::OsString;

    #[test]
    fn defaults_when_option_is_absent() {
        let parsed = extract_image_base_argument(&[OsString::from("start.o")]).unwrap();
        assert_eq!(parsed.image_base, DEFAULT_IMAGE_BASE);
        assert_eq!(parsed.arguments, vec![OsString::from("start.o")]);
    }

    #[test]
    fn normalizes_entry_equals_and_rejects_empty_before_io() {
        let parsed = extract_image_base_argument(&[
            OsString::from("--entry=custom_entry"),
            OsString::from("start.o"),
        ])
        .unwrap();
        assert_eq!(
            parsed.arguments,
            vec![
                OsString::from("--entry"),
                OsString::from("custom_entry"),
                OsString::from("start.o")
            ]
        );
        assert_eq!(
            extract_image_base_argument(&[OsString::from("--entry=")]).unwrap_err(),
            ImageBaseArgumentError::EmptyEntrySymbol
        );
    }

    #[test]
    fn accepts_hex_and_decimal_and_preserves_other_arguments() {
        let hex = extract_image_base_argument(&[
            OsString::from("start.o"),
            OsString::from("--image-base"),
            OsString::from("0x800000"),
            OsString::from("lib.a"),
        ])
        .unwrap();
        assert_eq!(hex.image_base, 0x800000);
        assert_eq!(
            hex.arguments,
            vec![OsString::from("start.o"), OsString::from("lib.a")]
        );

        let decimal = extract_image_base_argument(&[
            OsString::from("--image-base"),
            OsString::from("8388608"),
            OsString::from("start.o"),
        ])
        .unwrap();
        assert_eq!(decimal.image_base, 0x800000);

        let equals = extract_image_base_argument(&[
            OsString::from("--image-base=0x900000"),
            OsString::from("start.o"),
        ])
        .unwrap();
        assert_eq!(equals.image_base, 0x900000);
        assert_eq!(equals.arguments, vec![OsString::from("start.o")]);
    }

    #[test]
    fn parses_bounded_linker_script_grammar() {
        assert_eq!(
            parse_linker_script("SECTIONS { . = 0x800000; }").unwrap(),
            0x800000
        );
        assert_eq!(
            parse_linker_script("\nSECTIONS\n{\n. = 8388608 ;\n}\n").unwrap(),
            0x800000
        );
        assert_eq!(
            parse_linker_script("SECTIONS { .text 0x900000 : { *(.text) } }").unwrap(),
            0x900000
        );
        assert_eq!(
            parse_linker_script("\nSECTIONS {\n.text 9437184 :\n{ *( .text ) }\n}\n").unwrap(),
            0x900000
        );
        assert_eq!(
            parse_linker_script("SECTIONS { . = 0x900000; .text : { *(.text) } }").unwrap(),
            0x900000
        );
        assert_eq!(
            parse_linker_script("SECTIONS { . = 9437184 ;\n.text:\n{ *( .text ) } }").unwrap(),
            0x900000
        );
        assert_eq!(
            parse_linker_script("SECTIONS { . = 0x900000; .text : { *(.text .text.*) } }").unwrap(),
            0x900000
        );
        assert_eq!(
            parse_linker_script("SECTIONS { .text 0x900000 : { *( .text\n.text.* ) } }").unwrap(),
            0x900000
        );
        assert_eq!(
            parse_linker_script("SECTIONS { . = 0x900000; .text : { *(.text*) } }").unwrap(),
            0x900000
        );
        assert_eq!(
            parse_linker_script("SECTIONS { .text 0x900000 : { *( .text* ) } }").unwrap(),
            0x900000
        );
    }

    #[test]
    fn parses_c_style_comments_as_whitespace() {
        let parsed = parse_linker_script_config(
            "/* file header */ ENTRY(/* before */ custom_entry /* after */)\nSECTIONS { /* base */ . = 0x900000; /* output */ .text : { *(/* selector */ .text .text.*) } } /* tail */",
        )
        .unwrap();
        assert_eq!(parsed.image_base, 0x900000);
        assert_eq!(parsed.entry_symbol.as_deref(), Some("custom_entry"));
    }

    #[test]
    fn parses_bounded_entry_directive_before_sections() {
        let parsed = parse_linker_script_config(
            "ENTRY(custom_entry)\nSECTIONS { .text 0x900000 : { *(.text) } }",
        )
        .unwrap();
        assert_eq!(parsed.image_base, 0x900000);
        assert_eq!(parsed.entry_symbol.as_deref(), Some("custom_entry"));

        let sequenced = parse_linker_script_config(
            "ENTRY(custom_entry)\nSECTIONS { . = 0x900000; .text : { *(.text) } }",
        )
        .unwrap();
        assert_eq!(sequenced.image_base, 0x900000);
        assert_eq!(sequenced.entry_symbol.as_deref(), Some("custom_entry"));
    }

    #[test]
    fn rejects_malformed_and_overflowing_linker_scripts() {
        for script in [
            "/* unterminated",
            "SECTIONS { . = 0x800000; /* unterminated }",
            "SECTIONS { }",
            "SECTIONS { . = ; }",
            "SECTIONS { . = 0x10000000000000000; }",
            "SECTIONS { . = 0x800000; .text : {} }",
            "SECTIONS { . = 0x800000; .text : { *(.rodata) } }",
            "SECTIONS { . = 0x800000; .text : { *(.text.*) } }",
            "SECTIONS { . = 0x800000; .text : { *(.text**) } }",
            "SECTIONS { . = 0x800000; .text : { *(.text.* .text) } }",
            "SECTIONS { . = 0x800000; .text : { *(.text .text.foo) } }",
            "SECTIONS { . = 0x800000; .text : { *(.text .rodata*) } }",
            "SECTIONS { . = 0x800000; .text : { *(.text) } .data : { *(.data) } }",
            "ENTRY() SECTIONS { . = 0x800000; }",
            "ENTRY(two words) SECTIONS { . = 0x800000; }",
            "ENTRY(one) ENTRY(two) SECTIONS { . = 0x800000; }",
            "ENTRY(unclosed SECTIONS { . = 0x800000; }",
            "SECTIONS { .text 0x10000000000000000 : { *(.text) } }",
            "SECTIONS { .data 0x900000 : { *(.data) } }",
            "SECTIONS { .text 0x900000 : { *(.rodata) } }",
            "SECTIONS { .text 0x900000 : { *(.text) *(.rodata) } }",
            "SECTIONS { .text 0x900000 : { *(.text) } .data : { *(.data) } }",
        ] {
            assert!(
                parse_linker_script_config(script).is_err(),
                "accepted {script:?}"
            );
        }
    }

    #[test]
    fn rejects_missing_empty_duplicate_and_overflowing_values() {
        assert_eq!(
            extract_image_base_argument(&[OsString::from("--image-base")]).unwrap_err(),
            ImageBaseArgumentError::MissingValue
        );
        assert_eq!(
            extract_image_base_argument(&[
                OsString::from("--image-base"),
                OsString::new(),
                OsString::from("start.o"),
            ])
            .unwrap_err(),
            ImageBaseArgumentError::EmptyValue
        );
        assert_eq!(
            extract_image_base_argument(&[OsString::from("--image-base=")]).unwrap_err(),
            ImageBaseArgumentError::EmptyValue
        );
        assert_eq!(
            extract_image_base_argument(&[
                OsString::from("--image-base"),
                OsString::from("1"),
                OsString::from("--image-base"),
                OsString::from("2"),
            ])
            .unwrap_err(),
            ImageBaseArgumentError::DuplicateOption
        );
        assert!(matches!(
            extract_image_base_argument(&[
                OsString::from("--image-base"),
                OsString::from("0x10000000000000000"),
            ])
            .unwrap_err(),
            ImageBaseArgumentError::InvalidValue { .. }
        ));
    }

    #[test]
    fn rejects_duplicate_scripts_and_image_base_conflicts_before_io() {
        assert_eq!(
            extract_image_base_argument(&[
                OsString::from("-T"),
                OsString::from("one.ld"),
                OsString::from("--script"),
                OsString::from("two.ld"),
            ])
            .unwrap_err(),
            ImageBaseArgumentError::ReadScript {
                path: "one.ld".into(),
                message: std::fs::read("one.ld").unwrap_err().to_string(),
            }
        );
        assert_eq!(
            extract_image_base_argument(&[
                OsString::from("--image-base"),
                OsString::from("0x800000"),
                OsString::from("-T"),
                OsString::from("missing.ld"),
            ])
            .unwrap_err(),
            ImageBaseArgumentError::ConflictingSources
        );
        assert_eq!(
            extract_image_base_argument(&[
                OsString::from("--image-base"),
                OsString::from("0x800000"),
                OsString::from("-Tmissing.ld"),
            ])
            .unwrap_err(),
            ImageBaseArgumentError::ConflictingSources
        );
        assert_eq!(
            extract_image_base_argument(&[
                OsString::from("--image-base"),
                OsString::from("0x800000"),
                OsString::from("--script=missing.ld"),
            ])
            .unwrap_err(),
            ImageBaseArgumentError::ConflictingSources
        );
        assert_eq!(
            extract_image_base_argument(&[OsString::from("--script=")]).unwrap_err(),
            ImageBaseArgumentError::EmptyScriptPath
        );
    }
}
