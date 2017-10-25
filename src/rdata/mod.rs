//! Data types and methods for handling the RData field

#![allow(missing_docs)] // resource records are pretty self-descriptive

pub mod a;
pub mod aaaa;
pub mod all;
pub mod axfr;
pub mod caa;
pub mod cname;
pub mod hinfo;
pub mod maila;
pub mod mailb;
pub mod mb;
pub mod mf;
pub mod mg;
pub mod minfo;
pub mod mr;
pub mod mx;
pub mod ns;
pub mod null;
pub mod opt;
pub mod ptr;
pub mod soa;
pub mod srv;
pub mod txt;
pub mod wks;

pub use self::a::Record as A;
pub use self::aaaa::Record as Aaaa;
pub use self::caa::Record as Caa;
pub use self::cname::Record as Cname;
pub use self::mx::Record as Mx;
pub use self::ns::Record as Ns;
pub use self::opt::Record as Opt;
pub use self::ptr::Record as Ptr;
pub use self::soa::Record as Soa;
pub use self::srv::Record as Srv;
pub use self::txt::Record as Txt;

use {Type, Error};

/// The enumeration that represents known types of DNS resource records data
#[derive(Debug)]
pub enum RData<'a> {
    A(A),
    AAAA(Aaaa),
    CAA(Caa),
    CNAME(Cname<'a>),
    MX(Mx<'a>),
    NS(Ns<'a>),
    PTR(Ptr<'a>),
    SOA(Soa<'a>),
    SRV(Srv<'a>),
    TXT(Txt),
    /// Anything that can't be parsed yet
    Unknown(&'a [u8]),
}

/// A parser for RData
pub trait Parse<'a> {
    /// Parse an RR data and return RData enumeration
    fn parse(rdata: &'a [u8])
        -> Result<RData<'a>, Error>;
}

/// A parser for RData
pub trait ParseWithOriginal<'a> {
    /// Parse an RR data and return RData enumeration
    fn parse_with_original(rdata: &'a [u8], original: &'a [u8])
        -> Result<RData<'a>, Error>;
}

impl<'a> RData<'a> {
    /// Parse an RR data and return RData enumeration
    pub fn parse(typ: Type, rdata: &'a [u8], original: &'a [u8])
        -> Result<RData<'a>, Error>
    {
        match typ {
            Type::A         => A::parse(rdata),
            Type::AAAA      => Aaaa::parse(rdata),
            Type::CAA       => Caa::parse_with_original(rdata, original),
            Type::CNAME     => Cname::parse_with_original(rdata, original),
            Type::NS        => Ns::parse_with_original(rdata, original),
            Type::MX        => Mx::parse_with_original(rdata, original),
            Type::PTR       => Ptr::parse_with_original(rdata, original),
            Type::SOA       => Soa::parse_with_original(rdata, original),
            Type::SRV       => Srv::parse_with_original(rdata, original),
            Type::TXT       => Txt::parse(rdata),
            _               => Ok(RData::Unknown(rdata)),
        }
    }
}
