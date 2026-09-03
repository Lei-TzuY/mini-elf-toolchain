#![forbid(unsafe_code)]

pub mod elf64;
pub mod executable_pipeline;
pub mod executable_writer;
pub mod input_object;
pub mod layout;
pub mod link_context;
pub mod link_relocations;
pub mod link_symbols;
pub mod load_segments;
pub mod object_symbols;
pub mod output_image;
pub mod permission_layout;
pub mod rela_apply;
pub mod relocations;
pub mod resolve;
pub mod symbol_addresses;
pub mod symbol_names;
pub mod x86_64_relocations;
