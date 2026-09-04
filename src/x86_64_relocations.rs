use core::fmt;

use crate::relocations::Elf64Rela;

pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationValue {
    U64(u64),
    U32(u32),
    I32(i32),
}

impl RelocationValue {
    fn width(self) -> u64 {
        match self {
            Self::U64(_) => 8,
            Self::U32(_) | Self::I32(_) => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationEvaluationError {
    UnsupportedRelocationType { relocation_type: u32 },
    Unsigned64OutOfRange { value: i128 },
    Unsigned32OutOfRange { value: i128 },
    Signed32OutOfRange { value: i128 },
}

impl fmt::Display for RelocationEvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedRelocationType { relocation_type } => {
                write!(f, "unsupported x86-64 relocation type {relocation_type}")
            }
            Self::Unsigned64OutOfRange { value } => write!(
                f,
                "x86-64 absolute relocation result {value} is outside the unsigned 64-bit range"
            ),
            Self::Unsigned32OutOfRange { value } => write!(
                f,
                "x86-64 absolute relocation result {value} is outside the unsigned 32-bit range"
            ),
            Self::Signed32OutOfRange { value } => write!(
                f,
                "x86-64 signed 32-bit relocation result {value} is outside the signed 32-bit range"
            ),
        }
    }
}

impl std::error::Error for RelocationEvaluationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationApplyError {
    Evaluation(RelocationEvaluationError),
    TargetRangeOverflow {
        offset: u64,
        width: u64,
    },
    TargetOutOfBounds {
        offset: u64,
        width: u64,
        end: u64,
        section_len: usize,
    },
}

impl fmt::Display for RelocationApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evaluation(error) => write!(f, "{error}"),
            Self::TargetRangeOverflow { offset, width } => write!(
                f,
                "x86-64 relocation target range starting at offset {offset} with width {width} overflows u64"
            ),
            Self::TargetOutOfBounds {
                offset,
                width,
                end,
                section_len,
            } => write!(
                f,
                "x86-64 relocation target range [{offset}, {end}) with width {width} exceeds section length {section_len}"
            ),
        }
    }
}

impl std::error::Error for RelocationApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Evaluation(error) => Some(error),
            Self::TargetRangeOverflow { .. } | Self::TargetOutOfBounds { .. } => None,
        }
    }
}

impl From<RelocationEvaluationError> for RelocationApplyError {
    fn from(error: RelocationEvaluationError) -> Self {
        Self::Evaluation(error)
    }
}

pub fn evaluate_relocation(
    relocation: &Elf64Rela,
    symbol_value: u64,
    place: u64,
) -> Result<RelocationValue, RelocationEvaluationError> {
    let symbol_value = i128::from(symbol_value);
    let addend = i128::from(relocation.addend);
    let place = i128::from(place);

    match relocation.relocation_type {
        R_X86_64_64 => {
            let value = symbol_value + addend;
            let value = u64::try_from(value)
                .map_err(|_| RelocationEvaluationError::Unsigned64OutOfRange { value })?;
            Ok(RelocationValue::U64(value))
        }
        R_X86_64_PC32 => {
            let value = symbol_value + addend - place;
            let value = i32::try_from(value)
                .map_err(|_| RelocationEvaluationError::Signed32OutOfRange { value })?;
            Ok(RelocationValue::I32(value))
        }
        R_X86_64_32 => {
            let value = symbol_value + addend;
            let value = u32::try_from(value)
                .map_err(|_| RelocationEvaluationError::Unsigned32OutOfRange { value })?;
            Ok(RelocationValue::U32(value))
        }
        R_X86_64_32S => {
            let value = symbol_value + addend;
            let value = i32::try_from(value)
                .map_err(|_| RelocationEvaluationError::Signed32OutOfRange { value })?;
            Ok(RelocationValue::I32(value))
        }
        relocation_type => {
            Err(RelocationEvaluationError::UnsupportedRelocationType { relocation_type })
        }
    }
}

pub fn apply_relocation(
    section: &mut [u8],
    relocation: &Elf64Rela,
    symbol_value: u64,
    place: u64,
) -> Result<(), RelocationApplyError> {
    let value = evaluate_relocation(relocation, symbol_value, place)?;
    write_relocation_value(section, relocation.offset, value)
}

pub fn write_relocation_value(
    section: &mut [u8],
    offset: u64,
    value: RelocationValue,
) -> Result<(), RelocationApplyError> {
    let width = value.width();
    let end = offset
        .checked_add(width)
        .ok_or(RelocationApplyError::TargetRangeOverflow { offset, width })?;
    if end > section.len() as u64 {
        return Err(RelocationApplyError::TargetOutOfBounds {
            offset,
            width,
            end,
            section_len: section.len(),
        });
    }

    let start = offset as usize;
    let end = end as usize;
    match value {
        RelocationValue::U64(value) => section[start..end].copy_from_slice(&value.to_le_bytes()),
        RelocationValue::U32(value) => section[start..end].copy_from_slice(&value.to_le_bytes()),
        RelocationValue::I32(value) => section[start..end].copy_from_slice(&value.to_le_bytes()),
    }

    Ok(())
}
