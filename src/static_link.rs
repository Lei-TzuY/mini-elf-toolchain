use crate::executable_writer::ExecutableImage;
use crate::linker_input::LinkerInputObject;
use crate::program_headers::map_runtime_program_headers;

pub use crate::static_link_core::{StaticLinkError, StaticLinkOutput};

pub fn link_static_executable(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    entry_symbol: &[u8],
) -> Result<ExecutableImage, StaticLinkError> {
    let image = crate::static_link_core::link_static_executable(
        inputs,
        start_address,
        page_alignment,
        entry_symbol,
    )?;
    map_runtime_program_headers(image).map_err(StaticLinkError::Write)
}

pub fn link_static_executable_with_map(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    entry_symbol: &[u8],
) -> Result<StaticLinkOutput, StaticLinkError> {
    let mut output = crate::static_link_core::link_static_executable_with_map(
        inputs,
        start_address,
        page_alignment,
        entry_symbol,
    )?;
    output.image = map_runtime_program_headers(output.image).map_err(StaticLinkError::Write)?;

    debug_assert_eq!(output.link_map.segments.len(), output.image.load_segments.len());
    for (map_segment, image_segment) in output
        .link_map
        .segments
        .iter_mut()
        .zip(output.image.load_segments.iter())
    {
        map_segment.file_offset = image_segment.file_offset;
        map_segment.virtual_address = image_segment.virtual_address;
        map_segment.file_size = image_segment.file_size;
        map_segment.memory_size = image_segment.memory_size;
        map_segment.permissions = image_segment.permissions;
    }

    Ok(output)
}
