use {Name, Error};
use super::{Parse, ParseWithOriginal, RData, Txt};
use byteorder::ReadBytesExt;

pub (crate) const TYPE: isize = 257;

/// The CAA (Certification Authority Authorization) record
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Record {
    pub flags: u8,
    pub property: Property,
}

/// The CAA property according to RFC 6844
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Property {
    Issue(String),
    IssueWild(String),
    Iodef(String),
    Unknown { tag: String, value: String },
}

impl<'a> ParseWithOriginal<'a> for Record {
    fn parse_with_original(rdata: &'a [u8], original: &'a [u8]) -> Result<RData<'a>, Error> {
        let len = rdata.len();
        if len < 3 {
            return Err(Error::WrongRdataLength);
        }
        let flags = (&rdata[..1]).read_u8().unwrap();
        let tag = Name::scan(rdata, original)?;
        let mut pos = 0;
        pos += tag.byte_len();
        let value = if let RData::TXT(txt) = Txt::parse(&rdata[pos..])? {
            txt.0
        } else {
            unreachable!();
        };
        let property = match tag.to_string().as_str() {
            "issue"     => Property::Issue(value),
            "issuewild" => Property::IssueWild(value),
            "iodef"     => Property::Iodef(value),
            tag         => Property::Unknown { tag: tag.to_string(), value },
        };
        let record = Record { flags, property };
        Ok(RData::CAA(record))
    }
}
