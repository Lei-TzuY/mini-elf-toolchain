use core::fmt;

pub const ELF64_HEADER_SIZE: usize = 64;
pub const ELF64_PROGRAM_HEADER_SIZE: u16 = 56;
pub const ELF64_SECTION_HEADER_SIZE: u16 = 64;
pub const EM_X86_64: u16 = 62;
pub const SHT_NOBITS: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64Header {
    pub elf_type: u16,
    pub machine: u16,
    pub entry: u64,
    pub program_header_offset: u64,
    pub section_header_offset: u64,
    pub flags: u32,
    pub header_size: u16,
    pub program_header_entry_size: u16,
    pub program_header_count: u16,
    pub section_header_entry_size: u16,
    pub section_header_count: u16,
    pub section_name_string_table_index: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64SectionHeader {
    pub name_offset: u32,
    pub section_type: u32,
    pub flags: u64,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub address_alignment: u64,
    pub entry_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    TruncatedHeader {
        actual: usize,
    },
    BadMagic,
    UnsupportedClass(u8),
    UnsupportedEndianness(u8),
    UnsupportedIdentVersion(u8),
    UnsupportedMachine(u16),
    UnsupportedVersion(u32),
    InvalidHeaderSize(u16),
    InvalidProgramHeaderEntrySize(u16),
    InvalidSectionHeaderEntrySize(u16),
    TableRangeOverflow(&'static str),
    TableOutOfBounds {
        table: &'static str,
        end: u64,
        file_len: usize,
    },
    InvalidSectionNameStringTableIndex {
        index: u16,
        count: u16,
    },
    InvalidSectionAlignment {
        section_index: u16,
        alignment: u64,
    },
    SectionDataRangeOverflow {
        section_index: u16,
    },
    SectionDataOutOfBounds {
        section_index: u16,
        end: u64,
        file_len: usize,
    },
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { actual } => write!(
                f,
                "ELF64 header is truncated: got {actual} bytes, need {ELF64_HEADER_SIZE}"
            ),
            Self::BadMagic => write!(f, "invalid ELF magic"),
            Self::UnsupportedClass(class) => {
                write!(f, "unsupported ELF class {class}; expected ELF64")
            }
            Self::UnsupportedEndianness(data) => write!(
                f,
                "unsupported ELF data encoding {data}; expected little-endian"
            ),
            Self::UnsupportedIdentVersion(version) => {
                write!(f, "unsupported ELF identification version {version}")
            }
            Self::UnsupportedMachine(machine) => {
                write!(f, "unsupported ELF machine {machine}; expected x86-64")
            }
            Self::UnsupportedVersion(version) => write!(f, "unsupported ELF version {version}"),
            Self::InvalidHeaderSize(size) => write!(
                f,
                "invalid ELF64 header size {size}; expected {ELF64_HEADER_SIZE}"
            ),
            Self::InvalidProgramHeaderEntrySize(size) => write!(
                f,
                "invalid ELF64 program-header entry size {size}; expected {ELF64_PROGRAM_HEADER_SIZE}"
            ),
            Self::InvalidSectionHeaderEntrySize(size) => write!(
                f,
                "invalid ELF64 section-header entry size {size}; expected {ELF64_SECTION_HEADER_SIZE}"
            ),
            Self::TableRangeOverflow(table) => write!(f, "{table} table range overflows u64"),
            Self::TableOutOfBounds {
                table,
                end,
                file_len,
            } => write!(
                f,
                "{table} table ends at file offset {end}, beyond file length {file_len}"
            ),
            Self::InvalidSectionNameStringTableIndex { index, count } => write!(
                f,
                "section-name string-table index {index} is outside section-header count {count}"
            ),
            Self::InvalidSectionAlignment {
                section_index,
                alignment,
            } => write!(
                f,
                "section {section_index} has invalid alignment {alignment}; expected zero or a power of two"
            ),
            Self::SectionDataRangeOverflow { section_index } => {
                write!(f, "section {section_index} file range overflows u64")
            }
            Self::SectionDataOutOfBounds {
                section_index,
                end,
                file_len,
            } => write!(
                f,
                "section {section_index} data ends at file offset {end}, beyond file length {file_len}"
            ),
        }
    }
}

impl std::error::Error for ElfError {}

impl Elf64Header {
    pub fn parse(file: &[u8]) -> Result<Self, ElfError> {
        if file.len() < ELF64_HEADER_SIZE {
            return Err(ElfError::TruncatedHeader { actual: file.len() });
        }
        if file[0..4] != [0x7f, b'E', b'L', b'F'] {
            return Err(ElfError::BadMagic);
        }
        if file[4] != 2 {
            return Err(ElfError::UnsupportedClass(file[4]));
        }
        if file[5] != 1 {
            return Err(ElfError::UnsupportedEndianness(file[5]));
        }
        if file[6] != 1 {
            return Err(ElfError::UnsupportedIdentVersion(file[6]));
        }

        let header = Self {
            elf_type: read_u16(file, 16),
            machine: read_u16(file, 18),
            entry: read_u64(file, 24),
            program_header_offset: read_u64(file, 32),
            section_header_offset: read_u64(file, 40),
            flags: read_u32(file, 48),
            header_size: read_u16(file, 52),
            program_header_entry_size: read_u16(file, 54),
            program_header_count: read_u16(file, 56),
            section_header_entry_size: read_u16(file, 58),
            section_header_count: read_u16(file, 60),
            section_name_string_table_index: read_u16(file, 62),
        };

        let version = read_u32(file, 20);
        if header.machine != EM_X86_64 {
            return Err(ElfError::UnsupportedMachine(header.machine));
        }
        if version != 1 {
            return Err(ElfError::UnsupportedVersion(version));
        }
        if header.header_size != ELF64_HEADER_SIZE as u16 {
            return Err(ElfError::InvalidHeaderSize(header.header_size));
        }
        if header.program_header_count != 0
            && header.program_header_entry_size != ELF64_PROGRAM_HEADER_SIZE
        {
            return Err(ElfError::InvalidProgramHeaderEntrySize(
                header.program_header_entry_size,
            ));
        }
        if header.section_header_count != 0
            && header.section_header_entry_size != ELF64_SECTION_HEADER_SIZE
        {
            return Err(ElfError::InvalidSectionHeaderEntrySize(
                header.section_header_entry_size,
            ));
        }
        if header.section_name_string_table_index != 0
            && header.section_name_string_table_index >= header.section_header_count
        {
            return Err(ElfError::InvalidSectionNameStringTableIndex {
                index: header.section_name_string_table_index,
                count: header.section_header_count,
            });
        }

        validate_table_span(
            "program-header",
            header.program_header_offset,
            header.program_header_entry_size,
            header.program_header_count,
            file.len(),
        )?;
        validate_table_span(
            "section-header",
            header.section_header_offset,
            header.section_header_entry_size,
            header.section_header_count,
            file.len(),
        )?;

        Ok(header)
    }

    pub fn section_headers(&self, file: &[u8]) -> Result<Vec<Elf64SectionHeader>, ElfError> {
        validate_table_span(
            "section-header",
            self.section_header_offset,
            self.section_header_entry_size,
            self.section_header_count,
            file.len(),
        )?;
        if self.section_header_count != 0
            && self.section_header_entry_size != ELF64_SECTION_HEADER_SIZE
        {
            return Err(ElfError::InvalidSectionHeaderEntrySize(
                self.section_header_entry_size,
            ));
        }

        let mut sections = Vec::with_capacity(usize::from(self.section_header_count));
        for index in 0..self.section_header_count {
            let entry_offset = self
                .section_header_offset
                .checked_add(u64::from(index) * u64::from(ELF64_SECTION_HEADER_SIZE))
                .ok_or(ElfError::TableRangeOverflow("section-header"))?
                as usize;
            let section = Elf64SectionHeader {
                name_offset: read_u32(file, entry_offset),
                section_type: read_u32(file, entry_offset + 4),
                flags: read_u64(file, entry_offset + 8),
                address: read_u64(file, entry_offset + 16),
                offset: read_u64(file, entry_offset + 24),
                size: read_u64(file, entry_offset + 32),
                link: read_u32(file, entry_offset + 40),
                info: read_u32(file, entry_offset + 44),
                address_alignment: read_u64(file, entry_offset + 48),
                entry_size: read_u64(file, entry_offset + 56),
            };

            if section.address_alignment != 0 && !section.address_alignment.is_power_of_two() {
                return Err(ElfError::InvalidSectionAlignment {
                    section_index: index,
                    alignment: section.address_alignment,
                });
            }
            if section.section_type != SHT_NOBITS {
                let end = section.offset.checked_add(section.size).ok_or(
                    ElfError::SectionDataRangeOverflow {
                        section_index: index,
                    },
                )?;
                if end > file.len() as u64 {
                    return Err(ElfError::SectionDataOutOfBounds {
                        section_index: index,
                        end,
                        file_len: file.len(),
                    });
                }
            }

            sections.push(section);
        }
        Ok(sections)
    }
}

fn validate_table_span(
    table: &'static str,
    offset: u64,
    entry_size: u16,
    count: u16,
    file_len: usize,
) -> Result<(), ElfError> {
    if count == 0 {
        return Ok(());
    }

    let size = u64::from(entry_size)
        .checked_mul(u64::from(count))
        .ok_or(ElfError::TableRangeOverflow(table))?;
    let end = offset
        .checked_add(size)
        .ok_or(ElfError::TableRangeOverflow(table))?;
    if end > file_len as u64 {
        return Err(ElfError::TableOutOfBounds {
            table,
            end,
            file_len,
        });
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
