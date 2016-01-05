use {QueryType, QueryClass, ResponseCode, Name};

pub struct RawMessage<'a> {
    pub header: &'a [u8],
    pub question: &'a [u8],
    pub answer: &'a [u8],
    pub authority: &'a [u8],
    pub additional: &'a [u8],
}

pub struct Header {
    pub id: u16,
    pub query: bool,
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

pub struct Question<'a> {
    pub qname: Name<'a>,
    pub qtype: QueryType,
    pub qclass: QueryClass,
}

pub struct ResourceRecord<'a> {
    pub name: Name<'a>,
}
