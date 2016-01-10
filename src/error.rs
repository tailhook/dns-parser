quick_error! {
    #[derive(Debug)]
    pub enum Error {
        HeaderTooShort {
            description("packet is smaller than header size")
        }
        UnexpectedEOF {
            description("packet is has incomplete data")
        }
        ReservedBitsAreNonZero {
            description("packet has non-zero reserved bits")
        }
        UnknownLabelFormat {
            description("label in domain name has unknown label format")
        }
        InvalidResponseCode(code: u16) {
            description("response code is invalid")
            display("response code {} is invalid", code)
        }
        InvalidQueryType(code: u16) {
            description("query type code is invalid")
            display("query type {} is invalid", code)
        }
        InvalidQueryClass(code: u16) {
            description("query class code is invalid")
            display("query class {} is invalid", code)
        }
        LabelIsNotAscii {
            description("invalid characters encountered while reading label")
        }
        WrongState {
            description("parser is in the wrong state")
        }
    }
}
