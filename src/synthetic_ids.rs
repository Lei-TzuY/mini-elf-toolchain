pub(crate) const COMMON_OBJECT_INDEX: usize = usize::MAX;
pub(crate) const GOT_OBJECT_INDEX: usize = usize::MAX - 1;
pub(crate) const PIE_RUNTIME_OBJECT_INDEX: usize = usize::MAX - 2;
pub(crate) const SHARED_METADATA_OBJECT_INDEX: usize = usize::MAX - 3;
pub(crate) const PLT_OBJECT_INDEX: usize = usize::MAX - 4;
pub(crate) const PLT_GOT_OBJECT_INDEX: usize = usize::MAX - 5;
pub(crate) const DYNAMIC_INTERP_OBJECT_INDEX: usize = usize::MAX - 6;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn synthetic_object_indices_are_unique() {
        let indices = [
            COMMON_OBJECT_INDEX,
            GOT_OBJECT_INDEX,
            PIE_RUNTIME_OBJECT_INDEX,
            SHARED_METADATA_OBJECT_INDEX,
            PLT_OBJECT_INDEX,
            PLT_GOT_OBJECT_INDEX,
            DYNAMIC_INTERP_OBJECT_INDEX,
        ];
        assert_eq!(
            indices.into_iter().collect::<BTreeSet<_>>().len(),
            indices.len()
        );
    }
}
