use byteorder::{BigEndian, ByteOrder};

use {Header, Packet, Error, Question, Name, QueryType, QueryClass};
use {Type, Class, ResourceRecord, RRData};


impl<'a> Packet<'a> {
    pub fn parse(data: &[u8]) -> Result<Packet, Error> {
        let header = try!(Header::parse(data));
        let mut offset = Header::size();
        let mut questions = Vec::new();
        for _ in 0..header.questions {
            let name = try!(Name::scan(&data[offset..], data));
            offset += name.byte_len();
            if offset + 4 > data.len() {
                return Err(Error::UnexpectedEOF);
            }
            let qtype = try!(QueryType::parse(
                BigEndian::read_u16(&data[offset..offset+2])));
            offset += 2;
            let qclass = try!(QueryClass::parse(
                BigEndian::read_u16(&data[offset..offset+2])));
            offset += 2;
            questions.push(Question {
                qname: name,
                qtype: qtype,
                qclass: qclass,
            });
        }
        let mut answers = Vec::new();
        for _ in 0..header.answers {
            let name = try!(Name::scan(&data[offset..], data));
            offset += name.byte_len();
            if offset + 10 > data.len() {
                return Err(Error::UnexpectedEOF);
            }
            let typ = try!(Type::parse(
                BigEndian::read_u16(&data[offset..offset+2])));
            offset += 2;
            let cls = try!(Class::parse(
                BigEndian::read_u16(&data[offset..offset+2])));
            offset += 2;
            let ttl = BigEndian::read_u32(&data[offset..offset+4]);
            offset += 4;
            let rdlen = BigEndian::read_u16(&data[offset..offset+2]) as usize;
            offset += 2;
            if offset + rdlen > data.len() {
                return Err(Error::UnexpectedEOF);
            }
            let data = try!(RRData::parse(typ,
                &data[offset..offset+rdlen], data));
            answers.push(ResourceRecord {
                name: name,
                cls: cls,
                ttl: ttl,
                data: data,
            });
        }
        Ok(Packet {
            header: header,
            questions: questions,
            answers: answers,
            nameservers: Vec::new(), // TODO(tailhook)
            additional: Vec::new(), // TODO(tailhook)
        })
    }
}

#[cfg(test)]
mod test {

    use std::net::Ipv4Addr;
    use {Packet, Header};
    use Opcode::*;
    use ResponseCode::*;
    use QueryType as QT;
    use QueryClass as QC;
    use Class as C;
    use RRData;

    #[test]
    fn parse_example_query() {
        let query = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";
        let packet = Packet::parse(query).unwrap();
        assert_eq!(packet.header, Header {
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
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::A);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "example.com");
        assert_eq!(packet.answers.len(), 0);
    }

    #[test]
    fn parse_example_response() {
        let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                         \x07example\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xf8\
                         \x00\x04]\xb8\xd8\"";
        let packet = Packet::parse(response).unwrap();
        assert_eq!(packet.header, Header {
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
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::A);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "example.com");
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(&packet.answers[0].name.to_string()[..], "example.com");
        assert_eq!(packet.answers[0].cls, C::IN);
        assert_eq!(packet.answers[0].ttl, 1272);
        match packet.answers[0].data {
            RRData::A(addr) => {
                assert_eq!(addr, Ipv4Addr::new(93, 184, 216, 34));
            }
            ref x => panic!("Wrong rdata {:?}", x),
        }
    }

}

