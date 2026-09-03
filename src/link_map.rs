use core::fmt::Write;
use std::collections::BTreeMap;

use crate::executable_writer::{ExecutableImage, LoadSegmentPermissions};
use crate::layout::LaidOutSection;
use crate::relocated_sections::RelocatedSectionImage;
use crate::resolve::SymbolDefinition;
use crate::symbol_addresses::{final_symbol_address, FinalSymbolAddressError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMapSection {
    pub object_index: usize,
    pub section_index: u16,
    pub address: u64,
    pub size: u64,
    pub flags: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMapSymbol {
    pub name: Vec<u8>,
    pub object_index: usize,
    pub section_index: u16,
    pub address: u64,
    pub size: u64,
    pub binding: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMapSegment {
    pub file_offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub permissions: LoadSegmentPermissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMap {
    pub entry_symbol: Vec<u8>,
    pub entry_address: u64,
    pub sections: Vec<LinkMapSection>,
    pub symbols: Vec<LinkMapSymbol>,
    pub segments: Vec<LinkMapSegment>,
}

impl LinkMap {
    pub fn render(&self) -> String {
        let mut output = String::new();
        writeln!(
            output,
            "ENTRY {} {:#018x}",
            String::from_utf8_lossy(&self.entry_symbol),
            self.entry_address
        )
        .expect("writing to String cannot fail");

        writeln!(output, "SECTIONS").expect("writing to String cannot fail");
        for section in &self.sections {
            writeln!(
                output,
                "  {:#018x} {:#018x} obj={} sec={} flags={:#x}",
                section.address,
                section.size,
                section.object_index,
                section.section_index,
                section.flags
            )
            .expect("writing to String cannot fail");
        }

        writeln!(output, "SYMBOLS").expect("writing to String cannot fail");
        for symbol in &self.symbols {
            writeln!(
                output,
                "  {:#018x} {:#018x} bind={} obj={} sec={} {}",
                symbol.address,
                symbol.size,
                symbol.binding,
                symbol.object_index,
                symbol.section_index,
                String::from_utf8_lossy(&symbol.name)
            )
            .expect("writing to String cannot fail");
        }

        writeln!(output, "SEGMENTS").expect("writing to String cannot fail");
        for segment in &self.segments {
            writeln!(
                output,
                "  vaddr={:#018x} memsz={:#018x} fileoff={:#018x} filesz={:#018x} {}",
                segment.virtual_address,
                segment.memory_size,
                segment.file_offset,
                segment.file_size,
                permission_text(segment.permissions)
            )
            .expect("writing to String cannot fail");
        }

        output
    }
}

pub fn build_link_map(
    relocated: &[RelocatedSectionImage],
    definitions: &BTreeMap<Vec<u8>, SymbolDefinition>,
    image: &ExecutableImage,
    entry_symbol: &[u8],
) -> Result<LinkMap, FinalSymbolAddressError> {
    let layout = relocated
        .iter()
        .map(|section| LaidOutSection {
            object_index: section.object_index,
            section_index: section.section_index,
            address: section.address,
            size: section.size,
        })
        .collect::<Vec<_>>();

    let sections = relocated
        .iter()
        .map(|section| LinkMapSection {
            object_index: section.object_index,
            section_index: section.section_index,
            address: section.address,
            size: section.size,
            flags: section.flags,
        })
        .collect();

    let symbols = definitions
        .values()
        .map(|definition| {
            final_symbol_address(definition, &layout).map(|address| LinkMapSymbol {
                name: definition.name.clone(),
                object_index: definition.object_index,
                section_index: definition.symbol.section_index,
                address,
                size: definition.symbol.size,
                binding: definition.symbol.info >> 4,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let segments = image
        .load_segments
        .iter()
        .map(|segment| LinkMapSegment {
            file_offset: segment.file_offset,
            virtual_address: segment.virtual_address,
            file_size: segment.file_size,
            memory_size: segment.memory_size,
            permissions: segment.permissions,
        })
        .collect();

    Ok(LinkMap {
        entry_symbol: entry_symbol.to_vec(),
        entry_address: image.entry_address,
        sections,
        symbols,
        segments,
    })
}

fn permission_text(permissions: LoadSegmentPermissions) -> &'static str {
    match permissions {
        LoadSegmentPermissions::ReadOnly => "R",
        LoadSegmentPermissions::ReadExecute => "RX",
        LoadSegmentPermissions::ReadWrite => "RW",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf64::Elf64Symbol;
    use crate::executable_writer::ExecutableLoadSegment;
    use crate::resolve::STB_GLOBAL;

    #[test]
    fn renders_sections_symbols_and_segments_deterministically() {
        let relocated = vec![RelocatedSectionImage {
            object_index: 0,
            section_index: 1,
            address: 0x400000,
            size: 4,
            section_type: 1,
            flags: 0x6,
            alignment: 16,
            bytes: vec![0x90; 4],
        }];
        let mut definitions = BTreeMap::new();
        definitions.insert(
            b"_start".to_vec(),
            SymbolDefinition {
                name: b"_start".to_vec(),
                object_index: 0,
                table_section_index: 3,
                symbol_index: 1,
                symbol: Elf64Symbol {
                    name_offset: 1,
                    info: STB_GLOBAL << 4,
                    other: 0,
                    section_index: 1,
                    value: 0,
                    size: 4,
                },
            },
        );
        let image = ExecutableImage {
            bytes: Vec::new(),
            load_file_offset: 0x1000,
            load_virtual_address: 0x400000,
            load_memory_size: 4,
            entry_address: 0x400000,
            load_segments: vec![ExecutableLoadSegment {
                file_offset: 0x1000,
                virtual_address: 0x400000,
                file_size: 4,
                memory_size: 4,
                permissions: LoadSegmentPermissions::ReadExecute,
            }],
        };

        let map = build_link_map(&relocated, &definitions, &image, b"_start").unwrap();
        let rendered = map.render();

        assert!(rendered.contains("ENTRY _start 0x0000000000400000"));
        assert!(rendered.contains("obj=0 sec=1 flags=0x6"));
        assert!(rendered.contains("bind=1 obj=0 sec=1 _start"));
        assert!(rendered.contains("vaddr=0x0000000000400000"));
        assert!(rendered.contains(" RX\n"));
    }
}
