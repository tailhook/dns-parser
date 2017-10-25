use RData;

pub (crate) const TYPE: isize = 41;

/// RFC 6891 OPT RR
#[derive(Debug)]
pub struct Record<'a> {
    pub udp: u16,
    pub extrcode: u8,
    pub version: u8,
    pub flags: u16,
    pub data: RData<'a>,
}
