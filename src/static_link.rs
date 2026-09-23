use crate::executable_writer::ExecutableImage;
use crate::gnu_stack::{gnu_stack_policy, GnuStackPolicy};
use crate::linker_input::LinkerInputObject;
use crate::program_headers::{
    map_runtime_program_headers, map_runtime_program_headers_with_dynamic,
    map_runtime_program_headers_with_dynamic_and_stack, map_runtime_program_headers_with_stack,
    RuntimeDynamicProgramHeader, RuntimeStackProgramHeader,
};

pub use crate::gnu_stack::GnuStackPolicyError;
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
    let stack = gnu_stack_policy(inputs).map_err(StaticLinkError::GnuStack)?;
    map_static_program_headers(image, None, stack).map_err(StaticLinkError::Write)
}

pub fn link_static_position_independent_executable_with_map(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
    entry_symbol: &[u8],
) -> Result<StaticLinkOutput, StaticLinkError> {
    let artifact = crate::static_link_core::link_static_position_independent_artifact_with_map(
        inputs,
        page_alignment,
        entry_symbol,
    )?;
    let mut output = artifact.output;
    let stack = gnu_stack_policy(inputs).map_err(StaticLinkError::GnuStack)?;
    let dynamic = artifact.dynamic.map(|dynamic| RuntimeDynamicProgramHeader {
        address: dynamic.address,
        size: dynamic.size,
    });
    output.image =
        map_static_program_headers(output.image, dynamic, stack).map_err(StaticLinkError::Write)?;
    synchronize_link_map_segments(&mut output);
    Ok(output)
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
    let stack = gnu_stack_policy(inputs).map_err(StaticLinkError::GnuStack)?;
    output.image =
        map_static_program_headers(output.image, None, stack).map_err(StaticLinkError::Write)?;

    synchronize_link_map_segments(&mut output);
    Ok(output)
}

fn map_static_program_headers(
    image: ExecutableImage,
    dynamic: Option<RuntimeDynamicProgramHeader>,
    stack: Option<GnuStackPolicy>,
) -> Result<ExecutableImage, crate::executable_writer::ExecutableWriteError> {
    match (dynamic, stack) {
        (Some(dynamic), Some(stack)) => map_runtime_program_headers_with_dynamic_and_stack(
            image,
            dynamic,
            RuntimeStackProgramHeader {
                executable: stack.executable,
            },
        ),
        (Some(dynamic), None) => map_runtime_program_headers_with_dynamic(image, dynamic),
        (None, Some(stack)) => map_runtime_program_headers_with_stack(
            image,
            RuntimeStackProgramHeader {
                executable: stack.executable,
            },
        ),
        (None, None) => map_runtime_program_headers(image),
    }
}

fn synchronize_link_map_segments(output: &mut StaticLinkOutput) {
    debug_assert_eq!(
        output.link_map.segments.len(),
        output.image.load_segments.len()
    );
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
}
