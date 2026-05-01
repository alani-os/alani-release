//! `image` module boundary.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageDescriptor<'a> {
    pub name: &'a str,
    pub version: u32,
}

impl<'a> ImageDescriptor<'a> {
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
