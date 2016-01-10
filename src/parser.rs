use byteorder::{BigEndian, ByteOrder};

use {Header, Packet, Error, Question, Name, QueryType, QueryClass};


impl<'a> Packet<'a> {
    pub fn parse(data: &[u8]) -> Result<Packet, Error> {
        let header = try!(Header::parse(data));
        let mut offset = Header::size();
        let mut questions = Vec::new();
        for _ in 0..header.questions {
            let name = try!(Name::scan(&data[offset..], data));
            offset += name.byte_len();
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
        Ok(Packet {
            header: header,
            questions: questions,
            answers: Vec::new(), // TODO(tailhook)
            nameservers: Vec::new(), // TODO(tailhook)
            additional: Vec::new(), // TODO(tailhook)
        })
    }
}

#[cfg(test)]
mod test {

    use {Packet, Header};
    use Opcode::*;
    use ResponseCode::*;
    use QueryType::*;
    use QueryClass::*;

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
        assert_eq!(packet.questions[0].qtype, A);
        assert_eq!(packet.questions[0].qclass, IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "example.com");
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
        assert_eq!(packet.questions[0].qtype, A);
        assert_eq!(packet.questions[0].qclass, IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "example.com");
    }

}

