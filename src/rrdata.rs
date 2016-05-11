use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{BigEndian, ByteOrder};

use {Name, Type, Error, SoaRecord};


/// The enumeration that represents known types of DNS resource records data
#[derive(Debug)]
pub enum RRData<'a> {
    CNAME(Name<'a>),
    NS(Name<'a>),
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    SRV { priority: u16, weight: u16, port: u16, target: Name<'a> },
    SOA(SoaRecord<'a>),
    PTR(Name<'a>),
    MX { preference: u16, exchange: Name<'a> },
    // Anything that can't be parsed yet
    Unknown(&'a [u8]),
}

impl<'a> RRData<'a> {
    pub fn parse(typ: Type, rdata: &'a [u8], original: &'a [u8])
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
            Type::AAAA => {
                if rdata.len() != 16 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::AAAA(Ipv6Addr::new(
                    BigEndian::read_u16(&rdata[0..2]),
                    BigEndian::read_u16(&rdata[2..4]),
                    BigEndian::read_u16(&rdata[4..6]),
                    BigEndian::read_u16(&rdata[6..8]),
                    BigEndian::read_u16(&rdata[8..10]),
                    BigEndian::read_u16(&rdata[10..12]),
                    BigEndian::read_u16(&rdata[12..14]),
                    BigEndian::read_u16(&rdata[14..16]),
                )))
            }
            Type::CNAME => {
                Ok(RRData::CNAME(try!(Name::scan(rdata, original))))
            }
            Type::NS => {
                Ok(RRData::NS(try!(Name::scan(rdata, original))))
            }
            Type::MX => {
                if rdata.len() < 3 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::MX {
                    preference: BigEndian::read_u16(&rdata[..2]),
                    exchange: try!(Name::scan(&rdata[2..], original)),
                })
            }
            Type::PTR => {
                Ok(RRData::PTR(try!(Name::scan(rdata, original))))
            }
            Type::SOA => {
                let mut pos = 0;
                let primary_name_server = try!(Name::scan(rdata, original));
                pos += primary_name_server.byte_len();
                let mailbox = try!(Name::scan(&rdata[pos..], original));
                pos += mailbox.byte_len();
                if rdata[pos..].len() < 20 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::SOA(SoaRecord {
                    primary_ns: primary_name_server,
                    mailbox: mailbox,
                    serial: BigEndian::read_u32(&rdata[pos..(pos+4)]),
                    refresh: BigEndian::read_u32(&rdata[(pos+4)..(pos+8)]),
                    retry: BigEndian::read_u32(&rdata[(pos+8)..(pos+12)]),
                    expire: BigEndian::read_u32(&rdata[(pos+12)..(pos+16)]),
                    minimum_ttl: BigEndian::read_u32(&rdata[(pos+16)..(pos+20)]),
                }))
            }
            Type::SRV => {
                if rdata.len() < 7 {
                    return Err(Error::WrongRdataLength);
                }
                Ok(RRData::SRV {
                    priority: BigEndian::read_u16(&rdata[..2]),
                    weight: BigEndian::read_u16(&rdata[2..4]),
                    port: BigEndian::read_u16(&rdata[4..6]),
                    target: try!(Name::scan(&rdata[6..], original)),
                })
            }
            _ => {
                Ok(RRData::Unknown(rdata))
            }
        }
    }
}
