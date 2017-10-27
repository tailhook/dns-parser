use Error;

/// The CLASS value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Class {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete
    /// RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
}

/// The QCLASS value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QueryClass {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete
    /// RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
    /// Any class
    Any = 255,
}

/// The OPCODE value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Opcode {
    /// Normal query
    StandardQuery,
    /// Inverse query (query a name by IP)
    InverseQuery,
    /// Server status request
    ServerStatusRequest,
    /// Reserved opcode for future use
    Reserved(u16),
}

/// The RCODE value according to RFC 1035
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(missing_docs)] // names are from spec
pub enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Reserved(u8),
}

impl From<u16> for Opcode {
    fn from(code: u16) -> Opcode {
        use self::Opcode::*;
        match code {
            0 => StandardQuery,
            1 => InverseQuery,
            2 => ServerStatusRequest,
            x => Reserved(x),
        }
    }
}
impl Into<u16> for Opcode {
    fn into(self) -> u16 {
        use self::Opcode::*;
        match self {
            StandardQuery => 0,
            InverseQuery => 1,
            ServerStatusRequest => 2,
            Reserved(x) => x,
        }
    }
}

impl From<u8> for ResponseCode {
    fn from(code: u8) -> ResponseCode {
        use self::ResponseCode::*;
        match code {
            0       => NoError,
            1       => FormatError,
            2       => ServerFailure,
            3       => NameError,
            4       => NotImplemented,
            5       => Refused,
            6...15  => Reserved(code),
            x       => panic!("Invalid response code {}", x),
        }
    }
}
impl Into<u8> for ResponseCode {
    fn into(self) -> u8 {
        use self::ResponseCode::*;
        match self {
            NoError         => 0,
            FormatError     => 1,
            ServerFailure   => 2,
            NameError       => 3,
            NotImplemented  => 4,
            Refused         => 5,
            Reserved(code)  => code,
        }
    }
}

impl QueryClass {
    /// Parse a query class code
    pub fn parse(code: u16) -> Result<QueryClass, Error> {
        use self::QueryClass::*;
        match code {
            1   => Ok(IN),
            2   => Ok(CS),
            3   => Ok(CH),
            4   => Ok(HS),
            255 => Ok(Any),
            x   => Err(Error::InvalidQueryClass(x)),
        }
    }
}

impl Class {
    /// Parse a class code
    pub fn parse(code: u16) -> Result<Class, Error> {
        use self::Class::*;
        match code {
            1   => Ok(IN),
            2   => Ok(CS),
            3   => Ok(CH),
            4   => Ok(HS),
            x   => Err(Error::InvalidClass(x)),
        }
    }
}
