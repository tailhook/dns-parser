use std::net::Ipv4Addr;

use byteorder::{BigEndian, ByteOrder};

use {Name, Type, Error};


/// The enumeration that represents known types of DNS resource records data
#[derive(Debug)]
pub enum RRData<'a> {
    // Not implemented
    CNAME(Name<'a>),
    A(Ipv4Addr),
    // Not implemented
    SRV { priority: u16, weight: u16, port: u16, target: Name<'a> },
    // Not implemented
    MX { prefererence: u16, exchange: Name<'a> },
    // Anything that can't be parsed yet
    Unknown(&'a [u8]),
}

impl<'a> RRData<'a> {
    pub fn parse(typ: Type, rdata: &'a [u8], _original: &'a [u8])
        -> Result<RRData<'a>, Error>
    {
        match typ {
            Type::A => {
                if rdata.len() != 4 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::A(
                    Ipv4Addr::from(BigEndian::read_u32(rdata))))
            }
            _ => {
                Ok(RRData::Unknown(rdata))
            }
        }
    }
}
