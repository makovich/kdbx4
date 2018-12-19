use std::fmt::{self, Debug};
use std::ops::Range;

#[doc(hidden)]
pub struct Binaries(Vec<u8>, Vec<Range<usize>>);

impl Binaries {
    pub(crate) fn new(bytes: Vec<u8>, refs: Vec<Range<usize>>) -> Binaries {
        Binaries(bytes, refs)
    }
}

impl Debug for Binaries {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Binaries ({} bytes in {} blobs)",
            self.0.len(),
            self.1.len()
        )
    }
}
