use {QueryType, QueryClass, Name, Class, Header, RData};
use {RDataBuf};
use rdata::opt;


/// Parsed DNS packet
#[derive(Debug)]
#[allow(missing_docs)]  // should be covered by spec
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
    pub opt: Option<opt::Record<'a>>,
}

/// Owned analogue of `Packet`
#[derive(Debug,Hash,Ord,PartialOrd,Eq,PartialEq,Clone)]
#[allow(missing_docs)]
pub struct PacketBuf {
    pub header: Header,
    pub questions: Vec<QuestionBuf>,
    pub answers: Vec<ResourceRecordBuf>,
    pub nameservers: Vec<ResourceRecordBuf>,
    pub additional: Vec<ResourceRecordBuf>,
    pub opt: Option<opt::RecordBuf>,
}

impl<'a> Packet<'a> {
    /// Make fully owned, editable copy
    pub fn deep_clone(&self) -> PacketBuf {
        PacketBuf{
            header: self.header,
            questions: self.questions.iter().map(|x|x.deep_clone()).collect(),
            answers: self.answers.iter().map(|x|x.deep_clone()).collect(),
            nameservers: self.nameservers.iter().map(|x|x.deep_clone()).collect(),
            additional: self.additional.iter().map(|x|x.deep_clone()).collect(),
            opt: self.opt.as_ref().map(|x|x.deep_clone()),
        }
    }
}


/// A parsed chunk of data in the Query section of the packet
#[derive(Debug)]
#[allow(missing_docs)]  // should be covered by spec
pub struct Question<'a> {
    pub qname: Name<'a>,
    /// Whether or not we prefer unicast responses.
    /// This is used in multicast DNS.
    pub prefer_unicast: bool,
    pub qtype: QueryType,
    pub qclass: QueryClass,
}

/// Owned analogue of `Question`
#[derive(Debug,Hash,Ord,PartialOrd,Eq,PartialEq,Clone)]
#[allow(missing_docs)]
pub struct QuestionBuf {
    pub qname: String,
    pub prefer_unicast: bool,
    pub qtype: QueryType,
    pub qclass: QueryClass,
}

impl<'a> Question<'a> {
    /// Make fully owned, editable copy
    pub fn deep_clone(&self) -> QuestionBuf {
        QuestionBuf{
            qname: self.qname.to_string(),
            prefer_unicast: self.prefer_unicast,
            qtype: self.qtype,
            qclass: self.qclass,
        }
    }
}


/// A single DNS record
///
/// We aim to provide whole range of DNS records available. But as time is
/// limited we have some types of packets which are parsed and other provided
/// as unparsed slice of bytes.
#[derive(Debug)]
#[allow(missing_docs)]  // should be covered by spec
pub struct ResourceRecord<'a> {
    pub name: Name<'a>,
    /// Whether or not the set of resource records is fully contained in the
    /// packet, or whether there will be more resource records in future
    /// packets. Only used for multicast DNS.
    pub multicast_unique: bool,
    pub cls: Class,
    pub ttl: u32,
    pub data: RData<'a>,
}

/// Owned analogue of `ResourceRecord`
#[derive(Debug,Hash,Ord,PartialOrd,Eq,PartialEq,Clone)]
#[allow(missing_docs)]
pub struct ResourceRecordBuf {
    pub name: String,
    pub multicast_unique: bool,
    pub cls: Class,
    pub ttl: u32,
    pub data: RDataBuf,
}


impl<'a> ResourceRecord<'a> {
    /// Make fully owned, editable copy
    pub fn deep_clone(&self) -> ResourceRecordBuf {
        ResourceRecordBuf{
            name: self.name.to_string(),
            multicast_unique: self.multicast_unique,
            cls: self.cls,
            ttl: self.ttl,
            data: self.data.deep_clone(),
        }
    }
}
