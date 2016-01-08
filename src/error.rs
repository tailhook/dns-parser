quick_error! {
    #[derive(Debug)]
    pub enum Error {
        HeaderTooShort {
            description("packet is smaller than header size")
        }
        ReservedBitsAreNonZero {
            description("packet has non-zero reserved bits")
        }
        InvalidResponseCode(code: u16) {
            description("response code is invalid")
            display("response code {} is invalid", code)
        }
        WrongPacketLength(expected: u16, real: usize) {
            description("packet length doesn't header data")
            display("expected packet size {} but it's {}", expected, real)
        }
    }
}
