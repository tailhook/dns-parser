use std::net::Ipv4Addr;

use Error;
use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Ord, PartialOrd, Hash)]
pub struct Record(pub Ipv4Addr);

impl Record {
    pub fn write_to<W: ::std::io::Write>(&self,mut w: W) -> ::std::io::Result<()> {
        w.write_all(&self.0.octets())?;
        Ok(())
    }
}

impl super::RecordType for Record {
    const TYPE: isize = 1;
}

impl<'a> super::Record<'a> for Record {
    fn parse(rdata: &'a [u8], _original: &'a [u8]) -> super::RDataResult<'a> {
        if rdata.len() != 4 {
            return Err(Error::WrongRdataLength);
        }
        let address = Ipv4Addr::from(BigEndian::read_u32(rdata));
        let record = Record(address);
        Ok(super::RData::A(record))
    }
}
