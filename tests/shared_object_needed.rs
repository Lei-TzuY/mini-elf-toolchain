use mini_elf_toolchain::shared_object::{link_shared_object_with_needed, SharedObjectError};

#[test]
fn producer_rejects_empty_needed_name_before_other_link_work() {
    let result = link_shared_object_with_needed(&[], 0x1000, &[Vec::new()]);
    assert!(matches!(
        result,
        Err(SharedObjectError::EmptyNeededName {
            dependency_index: 0
        })
    ));
}

#[test]
fn producer_rejects_embedded_nul_in_needed_name_before_other_link_work() {
    let result =
        link_shared_object_with_needed(&[], 0x1000, &[b"libgood.so\0libhidden.so".to_vec()]);
    assert!(matches!(
        result,
        Err(SharedObjectError::NeededNameContainsNul {
            dependency_index: 0
        })
    ));
}
