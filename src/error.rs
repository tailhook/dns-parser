use std::str::Utf8Error;

quick_error! {
    /// Error parsing DNS packet
    #[derive(Debug)]
    pub enum Error {
        BadPointer {
            description("invalid compression pointer not pointing backwards \
                         when parsing label")
        }
        HeaderTooShort {
            description("packet is smaller than header size")
        }
        UnexpectedEOF {
            description("packet is has incomplete data")
        }
        WrongRdataLength {
            description("wrong (too short or too long) size of RDATA")
        }
        ReservedBitsAreNonZero {
            description("packet has non-zero reserved bits")
        }
        UnknownLabelFormat {
            description("label in domain name has unknown label format")
        }
        InvalidQueryType(code: u16) {
            description("query type code is invalid")
            display("query type {} is invalid", code)
        }
        InvalidQueryClass(code: u16) {
            description("query class code is invalid")
            display("query class {} is invalid", code)
        }
        InvalidType(code: u16) {
            description("type code is invalid")
            display("type {} is invalid", code)
        }
        InvalidClass(code: u16) {
            description("class code is invalid")
            display("class {} is invalid", code)
        }
        LabelIsNotAscii {
            description("invalid characters encountered while reading label")
        }
        TxtDataIsNotUTF8(error: Utf8Error) {
            description("invalid characters encountered while reading TXT")
            display("{:?}", error)
        }
        WrongState {
            description("parser is in the wrong state")
        }
        AdditionalOPT {
            description("additional OPT record found")
        }
    }
}
