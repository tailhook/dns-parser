/// RFC 6891 OPT RR
#[derive(Debug)]
pub struct Record<'a> {
    pub udp: u16,
    pub extrcode: u8,
    pub version: u8,
    pub flags: u16,
    pub data: super::RData<'a>,
}

#[derive(Debug, Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct RecordBuf {
    pub udp: u16,
    pub extrcode: u8,
    pub version: u8,
    pub flags: u16,
    pub data: super::RDataBuf,
}

impl<'a> Record<'a> {
    pub fn deep_clone(&self) -> RecordBuf {
        RecordBuf{
            udp: self.udp,
            extrcode: self.extrcode,
            version: self.version,
            flags: self.flags,
            data: self.data.deep_clone(),
        }
    }
}

impl RecordBuf {
    pub fn write_to<W: ::std::io::Write>(&self,_w: W) -> ::std::io::Result<()> {
        unimplemented!()
    }
}

impl<'a> super::RecordType for Record<'a> {
    const TYPE: isize = 41;
}
impl super::RecordType for RecordBuf {
    const TYPE: isize = 41;
}
impl<'a> super::Record<'a> for Record<'a> {


    fn parse(_rdata: &'a [u8], _original: &'a [u8]) -> super::RDataResult<'a> {
        unimplemented!();
    }
}
