use core::fmt;
use std::ffi::OsString;

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
        }
    }
}

impl std::error::Error for ImageBaseArgumentError {}

pub fn extract_image_base_argument(
    arguments: &[OsString],
) -> Result<ImageBaseArguments, ImageBaseArgumentError> {
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut image_base = DEFAULT_IMAGE_BASE;
    let mut seen = false;
    let mut index = 0usize;

    while index < arguments.len() {
        if arguments[index] != "--image-base" {
            remaining.push(arguments[index].clone());
            index += 1;
            continue;
        }

        if seen {
            return Err(ImageBaseArgumentError::DuplicateOption);
        }
        let value = arguments
            .get(index + 1)
            .ok_or(ImageBaseArgumentError::MissingValue)?;
        if value.is_empty() {
            return Err(ImageBaseArgumentError::EmptyValue);
        }
        let text = value.to_str().ok_or(ImageBaseArgumentError::NonUtf8Value)?;
        image_base = parse_address(text)?;
        seen = true;
        index += 2;
    }

    Ok(ImageBaseArguments {
        arguments: remaining,
        image_base,
    })
}

fn parse_address(text: &str) -> Result<u64, ImageBaseArgumentError> {
    let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() {
            None
        } else {
            u64::from_str_radix(hex, 16).ok()
        }
    } else {
        text.parse::<u64>().ok()
    };

    parsed.ok_or_else(|| ImageBaseArgumentError::InvalidValue {
        value: text.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{extract_image_base_argument, ImageBaseArgumentError, DEFAULT_IMAGE_BASE};
    use std::ffi::OsString;

    #[test]
    fn defaults_when_option_is_absent() {
        let parsed = extract_image_base_argument(&[OsString::from("start.o")]).unwrap();
        assert_eq!(parsed.image_base, DEFAULT_IMAGE_BASE);
        assert_eq!(parsed.arguments, vec![OsString::from("start.o")]);
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
}