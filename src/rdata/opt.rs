/// RFC 6891 OPT RR
#[derive(Debug)]
pub struct Record<'a> {
    pub udp: u16,
    pub extrcode: u8,
    pub version: u8,
    pub flags: u16,
    pub data: super::RData<'a>,
}

impl<'a> super::Record<'a> for Record<'a> {

    const TYPE: isize = 41;

    fn parse(rdata: &'a [u8], _original: &'a [u8]) -> super::RDataResult<'a> {
        Ok(super::RData::OPT(rdata))
    }
}
