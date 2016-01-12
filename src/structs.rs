use {QueryType, QueryClass, Name, Class, Header, RRData};


pub struct Packet<'a> {
    pub header: Header,
    pub questions: Vec<Question<'a>>,
    pub answers: Vec<ResourceRecord<'a>>,
    pub nameservers: Vec<ResourceRecord<'a>>,
    pub additional: Vec<ResourceRecord<'a>>,
}

pub struct Question<'a> {
    pub qname: Name<'a>,
    pub qtype: QueryType,
    pub qclass: QueryClass,
}

pub struct ResourceRecord<'a> {
    pub name: Name<'a>,
    pub cls: Class,
    pub ttl: u32,
    pub data: RRData<'a>,
}
