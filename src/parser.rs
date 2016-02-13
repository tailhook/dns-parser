use std::i32;

use byteorder::{BigEndian, ByteOrder};

use {Header, Packet, Error, Question, Name, QueryType, QueryClass};
use {Type, Class, ResourceRecord, RRData};


impl<'a> Packet<'a> {
    pub fn parse(data: &[u8]) -> Result<Packet, Error> {
        let header = try!(Header::parse(data));
        let mut offset = Header::size();
        let mut questions = Vec::with_capacity(header.questions as usize);
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
        let mut answers = Vec::with_capacity(header.answers as usize);
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
            let mut ttl = BigEndian::read_u32(&data[offset..offset+4]);
            if ttl > i32::MAX as u32 {
                ttl = 0;
            }
            offset += 4;
            let rdlen = BigEndian::read_u16(&data[offset..offset+2]) as usize;
            offset += 2;
            if offset + rdlen > data.len() {
                return Err(Error::UnexpectedEOF);
            }
            let data = try!(RRData::parse(typ,
                &data[offset..offset+rdlen], data));
            offset += rdlen;
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
    use ResponseCode::NoError;
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

    #[test]
    fn parse_multiple_answers() {
        let response = b"\x9d\xe9\x81\x80\x00\x01\x00\x06\x00\x00\x00\x00\
            \x06google\x03com\x00\x00\x01\x00\x01\xc0\x0c\
            \x00\x01\x00\x01\x00\x00\x00\xef\x00\x04@\xe9\
            \xa4d\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xef\
            \x00\x04@\xe9\xa4\x8b\xc0\x0c\x00\x01\x00\x01\
            \x00\x00\x00\xef\x00\x04@\xe9\xa4q\xc0\x0c\x00\
            \x01\x00\x01\x00\x00\x00\xef\x00\x04@\xe9\xa4f\
            \xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xef\x00\x04@\
            \xe9\xa4e\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xef\
            \x00\x04@\xe9\xa4\x8a";
        let packet = Packet::parse(response).unwrap();
        assert_eq!(packet.header, Header {
            id: 40425,
            query: false,
            opcode: StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            response_code: NoError,
            questions: 1,
            answers: 6,
            nameservers: 0,
            additional: 0,
        });
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::A);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "google.com");
        assert_eq!(packet.answers.len(), 6);
        let ips = vec![
            Ipv4Addr::new(64, 233, 164, 100),
            Ipv4Addr::new(64, 233, 164, 139),
            Ipv4Addr::new(64, 233, 164, 113),
            Ipv4Addr::new(64, 233, 164, 102),
            Ipv4Addr::new(64, 233, 164, 101),
            Ipv4Addr::new(64, 233, 164, 138),
        ];
        for i in 0..6 {
            assert_eq!(&packet.answers[i].name.to_string()[..], "google.com");
            assert_eq!(packet.answers[i].cls, C::IN);
            assert_eq!(packet.answers[i].ttl, 239);
            match packet.answers[i].data {
                RRData::A(addr) => {
                    assert_eq!(addr, ips[i]);
                }
                ref x => panic!("Wrong rdata {:?}", x),
            }
        }
    }

    #[test]
    fn parse_srv_query() {
        let query = b"[\xd9\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
            \x0c_xmpp-server\x04_tcp\x05gmail\x03com\x00\x00!\x00\x01";
        let packet = Packet::parse(query).unwrap();
        assert_eq!(packet.header, Header {
            id: 23513,
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
        assert_eq!(packet.questions[0].qtype, QT::SRV);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..],
            "_xmpp-server._tcp.gmail.com");
        assert_eq!(packet.answers.len(), 0);
    }

    #[test]
    fn parse_srv_response() {
        let response = b"[\xd9\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\
            \x0c_xmpp-server\x04_tcp\x05gmail\x03com\x00\x00!\x00\x01\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00 \x00\x05\x00\x00\
            \x14\x95\x0bxmpp-server\x01l\x06google\x03com\x00\xc0\x0c\x00!\
            \x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\x14\x95\
            \x04alt3\x0bxmpp-server\x01l\x06google\x03com\x00\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
            \x14\x95\x04alt1\x0bxmpp-server\x01l\x06google\x03com\x00\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
            \x14\x95\x04alt2\x0bxmpp-server\x01l\x06google\x03com\x00\
            \xc0\x0c\x00!\x00\x01\x00\x00\x03\x84\x00%\x00\x14\x00\x00\
            \x14\x95\x04alt4\x0bxmpp-server\x01l\x06google\x03com\x00";
        let packet = Packet::parse(response).unwrap();
        assert_eq!(packet.header, Header {
            id: 23513,
            query: false,
            opcode: StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            response_code: NoError,
            questions: 1,
            answers: 5,
            nameservers: 0,
            additional: 0,
        });
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::SRV);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..],
            "_xmpp-server._tcp.gmail.com");
        assert_eq!(packet.answers.len(), 5);
        let items = vec![
            (5, 0, 5269, "xmpp-server.l.google.com"),
            (20, 0, 5269, "alt3.xmpp-server.l.google.com"),
            (20, 0, 5269, "alt1.xmpp-server.l.google.com"),
            (20, 0, 5269, "alt2.xmpp-server.l.google.com"),
            (20, 0, 5269, "alt4.xmpp-server.l.google.com"),
        ];
        for i in 0..5 {
            assert_eq!(&packet.answers[i].name.to_string()[..],
                "_xmpp-server._tcp.gmail.com");
            assert_eq!(packet.answers[i].cls, C::IN);
            assert_eq!(packet.answers[i].ttl, 900);
            match *&packet.answers[i].data {
                RRData::SRV { priority, weight, port, target } => {
                    assert_eq!(priority, items[i].0);
                    assert_eq!(weight, items[i].1);
                    assert_eq!(port, items[i].2);
                    assert_eq!(target.to_string(), (items[i].3).to_string());
                }
                ref x => panic!("Wrong rdata {:?}", x),
            }
        }
    }

    #[test]
    fn parse_mx_response() {
        let response = b"\xe3\xe8\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\
            \x05gmail\x03com\x00\x00\x0f\x00\x01\xc0\x0c\x00\x0f\x00\x01\
            \x00\x00\x04|\x00\x1b\x00\x05\rgmail-smtp-in\x01l\x06google\xc0\
            \x12\xc0\x0c\x00\x0f\x00\x01\x00\x00\x04|\x00\t\x00\
            \n\x04alt1\xc0)\xc0\x0c\x00\x0f\x00\x01\x00\x00\x04|\
            \x00\t\x00(\x04alt4\xc0)\xc0\x0c\x00\x0f\x00\x01\x00\
            \x00\x04|\x00\t\x00\x14\x04alt2\xc0)\xc0\x0c\x00\x0f\
            \x00\x01\x00\x00\x04|\x00\t\x00\x1e\x04alt3\xc0)";
        let packet = Packet::parse(response).unwrap();
        assert_eq!(packet.header, Header {
            id: 58344,
            query: false,
            opcode: StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            response_code: NoError,
            questions: 1,
            answers: 5,
            nameservers: 0,
            additional: 0,
        });
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::MX);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..],
            "gmail.com");
        assert_eq!(packet.answers.len(), 5);
        let items = vec![
            ( 5, "gmail-smtp-in.l.google.com"),
            (10, "alt1.gmail-smtp-in.l.google.com"),
            (40, "alt4.gmail-smtp-in.l.google.com"),
            (20, "alt2.gmail-smtp-in.l.google.com"),
            (30, "alt3.gmail-smtp-in.l.google.com"),
        ];
        for i in 0..5 {
            assert_eq!(&packet.answers[i].name.to_string()[..],
                "gmail.com");
            assert_eq!(packet.answers[i].cls, C::IN);
            assert_eq!(packet.answers[i].ttl, 1148);
            match *&packet.answers[i].data {
                RRData::MX { preference, exchange } => {
                    assert_eq!(preference, items[i].0);
                    assert_eq!(exchange.to_string(), (items[i].1).to_string());
                }
                ref x => panic!("Wrong rdata {:?}", x),
            }
        }
    }

}

