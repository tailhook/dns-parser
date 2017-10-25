use std::net::Ipv4Addr;

use Error;
use super::{Parse, RData};
use byteorder::{BigEndian, ByteOrder};

pub (crate) const TYPE: isize = 1;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Record(pub Ipv4Addr);

impl<'a> Parse<'a> for Record {
    fn parse(rdata: &'a [u8]) -> Result<RData<'a>, Error> {
        if rdata.len() != 4 {
            return Err(Error::WrongRdataLength);
        }
        let address = Ipv4Addr::from(BigEndian::read_u32(rdata));
        let record = Record(address);
        Ok(RData::A(record))
    }
}
