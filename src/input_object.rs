use core::fmt;

use crate::elf64::{Elf64Header, Elf64SectionHeader, Elf64SymbolTable, ElfError};
use crate::relocations::{rela_tables, Elf64RelaTable, RelaError};

pub const ET_REL: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocatableObject {
    pub header: Elf64Header,
    pub sections: Vec<Elf64SectionHeader>,
    pub symbol_tables: Vec<Elf64SymbolTable>,
    pub rela_tables: Vec<Elf64RelaTable>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocatableObjectError {
    Elf(ElfError),
    UnsupportedElfType(u16),
    Rela(RelaError),
}

impl fmt::Display for RelocatableObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf(error) => write!(f, "{error}"),
            Self::UnsupportedElfType(elf_type) => write!(
                f,
                "unsupported ELF type {elf_type}; expected relocatable object (ET_REL)"
            ),
            Self::Rela(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for RelocatableObjectError {}

impl From<ElfError> for RelocatableObjectError {
    fn from(error: ElfError) -> Self {
        Self::Elf(error)
    }
}

impl From<RelaError> for RelocatableObjectError {
    fn from(error: RelaError) -> Self {
        Self::Rela(error)
    }
}

impl RelocatableObject {
    pub fn parse(file: &[u8]) -> Result<Self, RelocatableObjectError> {
        let header = Elf64Header::parse(file)?;
        if header.elf_type != ET_REL {
            return Err(RelocatableObjectError::UnsupportedElfType(header.elf_type));
        }

        let sections = header.section_headers(file)?;
        let symbol_tables = header.symbol_tables(file, &sections)?;
        let rela_tables = rela_tables(file, &sections, &symbol_tables)?;

        Ok(Self {
            header,
            sections,
            symbol_tables,
            rela_tables,
        })
    }
}
