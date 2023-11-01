//! Data types and methods for handling the RData field

#![allow(missing_docs)] // resource records are pretty self-descriptive

pub mod a;
pub mod aaaa;
pub mod all;
pub mod axfr;
pub mod cname;
pub mod hinfo;
pub mod https;
pub mod maila;
pub mod mailb;
pub mod mb;
pub mod mf;
pub mod mg;
pub mod minfo;
pub mod mr;
pub mod mx;
pub mod ns;
pub mod nsec;
pub mod null;
pub mod opt;
pub mod ptr;
pub mod soa;
pub mod srv;
pub mod svcb;
pub mod txt;
pub mod wks;

use {Type, Error};

pub use self::a::Record as A;
pub use self::aaaa::Record as Aaaa;
pub use self::cname::Record as Cname;
pub use self::https::Record as Https;
pub use self::mx::Record as Mx;
pub use self::ns::Record as Ns;
pub use self::nsec::Record as Nsec;
pub use self::opt::Record as Opt;
pub use self::ptr::Record as Ptr;
pub use self::soa::Record as Soa;
pub use self::srv::Record as Srv;
pub use self::svcb::Record as Svcb;
pub use self::txt::Record as Txt;

pub type RDataResult<'a> = Result<RData<'a>, Error>;

/// The enumeration that represents known types of DNS resource records data
#[derive(Debug)]
pub enum RData<'a> {
    A(A),
    AAAA(Aaaa),
    CNAME(Cname<'a>),
    HTTPS(Https<'a>),
    MX(Mx<'a>),
    NS(Ns<'a>),
    PTR(Ptr<'a>),
    SOA(Soa<'a>),
    SRV(Srv<'a>),
    SVCB(Svcb<'a>),
    TXT(Txt<'a>),
    /// Anything that can't be parsed yet
    Unknown(Type, &'a [u8]),
}

pub (crate) trait Record<'a> {
    const TYPE: isize;

    fn parse(rdata: &'a [u8], original: &'a [u8]) -> RDataResult<'a>;
}

impl<'a> RData<'a> {
    /// Parse an RR data and return RData enumeration
    pub fn parse(typ: Type, rdata: &'a [u8], original: &'a [u8]) -> RDataResult<'a> {
        match typ {
            Type::A         => A::parse(rdata, original),
            Type::AAAA      => Aaaa::parse(rdata, original),
            Type::CNAME     => Cname::parse(rdata, original),
            Type::HTTPS     => Https::parse(rdata, original),
            Type::NS        => Ns::parse(rdata, original),
            Type::MX        => Mx::parse(rdata, original),
            Type::PTR       => Ptr::parse(rdata, original),
            Type::SOA       => Soa::parse(rdata, original),
            Type::SRV       => Srv::parse(rdata, original),
            Type::SVCB      => Svcb::parse(rdata, original),
            Type::TXT       => Txt::parse(rdata, original),
            _               => Ok(RData::Unknown(typ, rdata)),
        }
    }

    /// Returns packet type as enum
    ///
    /// Code can be converted to an integer `packet.type_code() as isize`
    pub fn type_code(self) -> Type {
        match self {
            RData::A(..)         => Type::A,
            RData::AAAA(..)      => Type::AAAA,
            RData::CNAME(..)     => Type::CNAME,
            RData::HTTPS(..)     => Type::HTTPS,
            RData::NS(..)        => Type::NS,
            RData::MX(..)        => Type::MX,
            RData::PTR(..)       => Type::PTR,
            RData::SOA(..)       => Type::SOA,
            RData::SRV(..)       => Type::SRV,
            RData::SVCB(..)      => Type::SVCB,
            RData::TXT(..)       => Type::TXT,
            RData::Unknown(t, _) => t,
        }
    }
}
