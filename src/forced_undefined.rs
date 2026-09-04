use core::fmt;
use std::ffi::{OsStr, OsString};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForcedUndefinedArguments {
    pub arguments: Vec<OsString>,
    pub symbols: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForcedUndefinedArgumentError {
    MissingSymbol,
    EmptySymbol,
}

impl fmt::Display for ForcedUndefinedArgumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSymbol => write!(f, "missing symbol after -u/--undefined"),
            Self::EmptySymbol => write!(f, "forced undefined symbol cannot be empty"),
        }
    }
}

impl std::error::Error for ForcedUndefinedArgumentError {}

pub fn extract_forced_undefined_arguments(
    arguments: &[OsString],
) -> Result<ForcedUndefinedArguments, ForcedUndefinedArgumentError> {
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut symbols = Vec::new();
    let mut index = 0usize;

    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "-u" || argument == "--undefined" {
            let symbol = arguments
                .get(index + 1)
                .ok_or(ForcedUndefinedArgumentError::MissingSymbol)?;
            push_symbol(symbol, &mut symbols)?;
            index += 2;
            continue;
        }
        if let Some(symbol) = strip_os_prefix(argument, "-u") {
            push_symbol(&symbol, &mut symbols)?;
            index += 1;
            continue;
        }

        remaining.push(argument.clone());
        index += 1;
    }

    Ok(ForcedUndefinedArguments {
        arguments: remaining,
        symbols,
    })
}

fn push_symbol(
    symbol: &OsStr,
    symbols: &mut Vec<Vec<u8>>,
) -> Result<(), ForcedUndefinedArgumentError> {
    if symbol.is_empty() {
        return Err(ForcedUndefinedArgumentError::EmptySymbol);
    }
    symbols.push(os_bytes(symbol));
    Ok(())
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

#[cfg(unix)]
fn strip_os_prefix(value: &OsStr, prefix: &str) -> Option<OsString> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let bytes = value.as_bytes();
    let prefix = prefix.as_bytes();
    (bytes.len() > prefix.len() && bytes.starts_with(prefix))
        .then(|| OsString::from_vec(bytes[prefix.len()..].to_vec()))
}

#[cfg(windows)]
fn strip_os_prefix(value: &OsStr, prefix: &str) -> Option<OsString> {
    let text = value.to_str()?;
    text.strip_prefix(prefix)
        .filter(|suffix| !suffix.is_empty())
        .map(OsString::from)
}

#[cfg(test)]
mod tests {
    use super::{
        extract_forced_undefined_arguments, ForcedUndefinedArgumentError, ForcedUndefinedArguments,
    };
    use std::ffi::OsString;

    #[test]
    fn extracts_split_long_and_joined_forms_without_reordering_inputs() {
        let parsed = extract_forced_undefined_arguments(&[
            OsString::from("root.o"),
            OsString::from("-ufoo"),
            OsString::from("liba.a"),
            OsString::from("--undefined"),
            OsString::from("bar"),
            OsString::from("-u"),
            OsString::from("baz"),
            OsString::from("libb.a"),
        ])
        .expect("forced undefined arguments should parse");

        assert_eq!(
            parsed,
            ForcedUndefinedArguments {
                arguments: vec![OsString::from("root.o"), OsString::from("liba.a"), OsString::from("libb.a")],
                symbols: vec![b"foo".to_vec(), b"bar".to_vec(), b"baz".to_vec()],
            }
        );
    }

    #[test]
    fn rejects_missing_and_empty_symbols_before_io() {
        assert_eq!(
            extract_forced_undefined_arguments(&[OsString::from("-u")]),
            Err(ForcedUndefinedArgumentError::MissingSymbol)
        );
        assert_eq!(
            extract_forced_undefined_arguments(&[
                OsString::from("--undefined"),
                OsString::new(),
            ]),
            Err(ForcedUndefinedArgumentError::EmptySymbol)
        );
    }
}
