use core::fmt;

use crate::relocations::Elf64Rela;

pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationValue {
    U64(u64),
    I32(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationEvaluationError {
    UnsupportedRelocationType { relocation_type: u32 },
    Unsigned64OutOfRange { value: i128 },
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
            Self::Signed32OutOfRange { value } => write!(
                f,
                "x86-64 PC-relative relocation result {value} is outside the signed 32-bit range"
            ),
        }
    }
}

impl std::error::Error for RelocationEvaluationError {}

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
        relocation_type => {
            Err(RelocationEvaluationError::UnsupportedRelocationType { relocation_type })
        }
    }
}
