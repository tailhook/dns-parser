//! Data types and methods for handling the RData field

#![allow(missing_docs)] // resource records are pretty self-descriptive

pub mod a;
pub mod aaaa;
pub mod all;
pub mod axfr;
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
pub mod nsec;
pub mod null;
pub mod opt;
pub mod ptr;
pub mod soa;
pub mod srv;
pub mod txt;
pub mod wks;

use {Type, Error};

pub use self::a::Record as A;
pub use self::aaaa::Record as Aaaa;
pub use self::cname::Record as Cname;
pub use self::mx::Record as Mx;
pub use self::ns::Record as Ns;
pub use self::nsec::Record as Nsec;
pub use self::opt::Record as Opt;
pub use self::ptr::Record as Ptr;
pub use self::soa::Record as Soa;
pub use self::srv::Record as Srv;
pub use self::txt::Record as Txt;

pub use self::cname::RecordBuf as CnameBuf;
pub use self::mx::RecordBuf as MxBuf;
pub use self::ns::RecordBuf as NsBuf;
pub use self::opt::RecordBuf as OptBuf;
pub use self::ptr::RecordBuf as PtrBuf;
pub use self::soa::RecordBuf as SoaBuf;
pub use self::srv::RecordBuf as SrvBuf;
pub use self::txt::RecordBuf as TxtBuf;

pub type RDataResult<'a> = Result<RData<'a>, Error>;

/// The enumeration that represents known types of DNS resource records data
#[derive(Debug)]
pub enum RData<'a> {
    A(A),
    AAAA(Aaaa),
    CNAME(Cname<'a>),
    MX(Mx<'a>),
    NS(Ns<'a>),
    PTR(Ptr<'a>),
    SOA(Soa<'a>),
    SRV(Srv<'a>),
    TXT(Txt<'a>),
    /// Anything that can't be parsed yet
    Unknown(Type, &'a [u8]),
}

/// Owned analogue of `RData`
#[derive(Debug,Clone,Ord,Eq,Hash,PartialOrd,PartialEq)]
pub enum RDataBuf {
    A(A),
    AAAA(Aaaa),
    CNAME(CnameBuf),
    MX(MxBuf),
    NS(NsBuf),
    PTR(PtrBuf),
    SOA(SoaBuf),
    SRV(SrvBuf),
    TXT(TxtBuf),
    /// Anything that can't be parsed yet
    Unknown(Type, Vec<u8>),
}


impl<'a> RData<'a> {
    pub fn deep_clone(&self) -> RDataBuf {
        match self {
            RData::A(x) => RDataBuf::A(*x),
            RData::AAAA(x) => RDataBuf::AAAA(*x),
            RData::CNAME(x) => RDataBuf::CNAME(x.deep_clone()),
            RData::MX(x) => RDataBuf::MX(x.deep_clone()),
            RData::NS(x) => RDataBuf::NS(x.deep_clone()),
            RData::PTR(x) => RDataBuf::PTR(x.deep_clone()),
            RData::SOA(x) => RDataBuf::SOA(x.deep_clone()),
            RData::SRV(x) => RDataBuf::SRV(x.deep_clone()),
            RData::TXT(x) => RDataBuf::TXT(x.deep_clone()),
            RData::Unknown(t, b) => RDataBuf::Unknown(*t, b.to_vec()),
        }
    }
}

impl RDataBuf {
    /// Serialize it as a part of DNS packet
    pub fn write_to<W: ::std::io::Write>(&self,mut w: W) -> ::std::io::Result<()> {
        match self {
            RDataBuf::A(x) => x.write_to(w),
            RDataBuf::AAAA(x) => x.write_to(w),
            RDataBuf::CNAME(x) => x.write_to(w),
            RDataBuf::MX(x) => x.write_to(w),
            RDataBuf::NS(x) => x.write_to(w),
            RDataBuf::PTR(x) => x.write_to(w),
            RDataBuf::SOA(x) => x.write_to(w),
            RDataBuf::SRV(x) => x.write_to(w),
            RDataBuf::TXT(x) => x.write_to(w),
            RDataBuf::Unknown(_t, b) => w.write_all(&b),
        }
    }
    
    /// Returns packet type as enum
    ///
    /// Code can be converted to an integer `packet.type_code() as isize`
    pub fn type_code(&self) -> Type {
        match *self {
            RDataBuf::A(..)         => Type::A,
            RDataBuf::AAAA(..)      => Type::AAAA,
            RDataBuf::CNAME(..)     => Type::CNAME,
            RDataBuf::NS(..)        => Type::NS,
            RDataBuf::MX(..)        => Type::MX,
            RDataBuf::PTR(..)       => Type::PTR,
            RDataBuf::SOA(..)       => Type::SOA,
            RDataBuf::SRV(..)       => Type::SRV,
            RDataBuf::TXT(..)       => Type::TXT,
            RDataBuf::Unknown(t, _) => t,
        }
    }
}

pub (crate) trait RecordType {
    const TYPE: isize;
}

pub (crate) trait Record<'a> : RecordType {
    fn parse(rdata: &'a [u8], original: &'a [u8]) -> RDataResult<'a>;
}

impl<'a> RData<'a> {
    /// Parse an RR data and return RData enumeration
    pub fn parse(typ: Type, rdata: &'a [u8], original: &'a [u8]) -> RDataResult<'a> {
        match typ {
            Type::A         => A::parse(rdata, original),
            Type::AAAA      => Aaaa::parse(rdata, original),
            Type::CNAME     => Cname::parse(rdata, original),
            Type::NS        => Ns::parse(rdata, original),
            Type::MX        => Mx::parse(rdata, original),
            Type::PTR       => Ptr::parse(rdata, original),
            Type::SOA       => Soa::parse(rdata, original),
            Type::SRV       => Srv::parse(rdata, original),
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
            RData::NS(..)        => Type::NS,
            RData::MX(..)        => Type::MX,
            RData::PTR(..)       => Type::PTR,
            RData::SOA(..)       => Type::SOA,
            RData::SRV(..)       => Type::SRV,
            RData::TXT(..)       => Type::TXT,
            RData::Unknown(t, _) => t,
        }
    }
}
