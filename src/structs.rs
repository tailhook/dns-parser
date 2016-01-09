use std::net::Ipv4Addr;

use {QueryType, QueryClass, ResponseCode, Name, Type, Class, Opcode};

pub enum RRData<'a> {
    CNAME(Name<'a>),
    A(Ipv4Addr),
    SRV { priority: u16, weight: u16, port: u16, target: Name<'a> },
    MX { prefererence: u16, exchange: Name<'a> },
    Unknown(&'a [u8]),
}

pub struct Question<'a> {
    pub qname: Name<'a>,
    pub qtype: QueryType,
    pub qclass: QueryClass,
}

pub struct RawResrouceRecord<'a> {
    pub name: Name<'a>,
    pub typ: Type,
    pub cls: Class,
    pub ttl: u32,
    pub data: &'a [u8],
}

pub struct ResourceRecord<'a> {
    pub name: Name<'a>,
    pub cls: Class,
    pub ttl: u32,
    pub data: RRData<'a>,
}
