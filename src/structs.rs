use {QueryType, QueryClass, Name, Class, Header, RRData};


/// Parsed DNS packet
#[derive(Debug)]
pub struct Packet<'a> {
    pub header: Header,
    pub questions: Vec<Question<'a>>,
    pub answers: Vec<ResourceRecord<'a>>,
    pub nameservers: Vec<ResourceRecord<'a>>,
    pub additional: Vec<ResourceRecord<'a>>,
    /// Optional Pseudo-RR
    /// When present it is sent as an RR in the additional section. In this RR
    /// the `class` and `ttl` fields store max udp packet size and flags
    /// respectively. To keep `ResourceRecord` clean we store the OPT record
    /// here.
    pub opt: Option<OptRecord<'a>>,
}

/// A parsed chunk of data in the Query section of the packet
#[derive(Debug)]
pub struct Question<'a> {
    pub qname: Name<'a>,
    pub qtype: QueryType,
    pub qclass: QueryClass,
}

/// A single DNS record
///
/// We aim to provide whole range of DNS records available. But as time is
/// limited we have some types of packets which are parsed and other provided
/// as unparsed slice of bytes.
#[derive(Debug)]
pub struct ResourceRecord<'a> {
    pub name: Name<'a>,
    pub cls: Class,
    pub ttl: u32,
    pub data: RRData<'a>,
}

/// RFC 6891 OPT RR
#[derive(Debug)]
pub struct OptRecord<'a> {
    pub udp: u16,
    pub extrcode: u8,
    pub version: u8,
    pub flags: u16,
    pub data: RRData<'a>,
}

#[derive(Debug)]
pub struct SoaRecord<'a> {
    pub primary_ns: Name<'a>,
    pub mailbox: Name<'a>,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum_ttl: u32,
}
