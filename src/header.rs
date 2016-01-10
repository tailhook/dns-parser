use byteorder::{BigEndian, ByteOrder};

use {Error, ResponseCode, Opcode};

mod flag {
    pub const QUERY:               u16 = 0b1000_0000_0000_0000;
    pub const OPCODE_MASK:         u16 = 0b0111_1000_0000_0000;
    pub const AUTHORITATIVE:       u16 = 0b0000_0100_0000_0000;
    pub const TRUNCATED:           u16 = 0b0000_0010_0000_0000;
    pub const RECURSION_DESIRED:   u16 = 0b0000_0001_0000_0000;
    pub const RECURSION_AVAILABLE: u16 = 0b0000_0000_1000_0000;
    pub const RESERVED_MASK:       u16 = 0b0000_0000_0111_0000;
    pub const RESPONSE_CODE_MASK:  u16 = 0b0000_0000_0000_1111;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Header {
    pub id: u16,
    pub query: bool,
    pub opcode: Opcode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: ResponseCode,
    pub questions: u16,
    pub answers: u16,
    pub nameservers: u16,
    pub additional: u16,
}

impl Header {
    pub fn parse(data: &[u8]) -> Result<Header, Error> {
        if data.len() < 12 {
            return Err(Error::HeaderTooShort);
        }
        let flags = BigEndian::read_u16(&data[2..4]);
        if flags & flag::RESERVED_MASK != 0 {
            return Err(Error::ReservedBitsAreNonZero);
        }
        let header = Header {
            id: BigEndian::read_u16(&data[..2]),
            query: flags & flag::QUERY == 0,
            opcode: (flags & flag::OPCODE_MASK
                     >> flag::OPCODE_MASK.trailing_zeros()).into(),
            authoritative: flags & flag::AUTHORITATIVE != 0,
            truncated: flags & flag::TRUNCATED != 0,
            recursion_desired: flags & flag::RECURSION_DESIRED != 0,
            recursion_available: flags & flag::RECURSION_AVAILABLE != 0,
            response_code: try!(ResponseCode::parse(
                flags & flag::RESPONSE_CODE_MASK)),
            questions: BigEndian::read_u16(&data[4..6]),
            answers: BigEndian::read_u16(&data[6..8]),
            nameservers: BigEndian::read_u16(&data[8..10]),
            additional: BigEndian::read_u16(&data[10..12]),
        };
        Ok(header)
    }
    pub fn size() -> usize { 12 }
}


#[cfg(test)]
mod test {

    use {Header};
    use Opcode::*;
    use ResponseCode::*;

    #[test]
    fn parse_example_query() {
        let query = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";
        let header = Header::parse(query).unwrap();
        assert_eq!(header, Header {
            id: 1573,
            query: true,
            opcode: StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: false,
            response_code: NoError,
            questions: 1,
            answers: 0,
            nameservers: 0,
            additional: 0,
        });
    }

    #[test]
    fn parse_example_response() {
        let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                         \x07example\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xf8\
                         \x00\x04]\xb8\xd8\"";
        let header = Header::parse(response).unwrap();
        assert_eq!(header, Header {
            id: 1573,
            query: false,
            opcode: StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            response_code: NoError,
            questions: 1,
            answers: 1,
            nameservers: 0,
            additional: 0,
        });
    }
}
