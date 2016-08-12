use std::i32;

use byteorder::{BigEndian, ByteOrder};

use {Header, Packet, Error, Question, Name, QueryType, QueryClass};
use {Type, Class, ResourceRecord, OptRecord, RRData};

const OPT_RR_START: [u8; 3] = [0, 0, 41];

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
            answers.push(try!(parse_record(data, &mut offset)));
        }
        let mut nameservers = Vec::with_capacity(header.nameservers as usize);
        for _ in 0..header.nameservers {
            nameservers.push(try!(parse_record(data, &mut offset)));
        }
        let mut additional = Vec::with_capacity(header.additional as usize);
        let mut opt = None;
        for _ in 0..header.additional {
            if data[offset..offset+3] == OPT_RR_START {
                opt = parse_opt_record(data, &mut offset).ok();
            } else {
                additional.push(try!(parse_record(data, &mut offset)));
            }
        }
        Ok(Packet {
            header: header,
            questions: questions,
            answers: answers,
            nameservers: nameservers,
            additional: additional,
            opt: opt,
        })
    }
}

// Generic function to parse answer, nameservers, and additional records.
fn parse_record<'a>(data: &'a [u8], offset: &mut usize) -> Result<ResourceRecord<'a>, Error> {
    let name = try!(Name::scan(&data[*offset..], data));
    *offset += name.byte_len();
    if *offset + 10 > data.len() {
        return Err(Error::UnexpectedEOF);
    }
    let typ = try!(Type::parse(
        BigEndian::read_u16(&data[*offset..*offset+2])));
    *offset += 2;
    let cls = try!(Class::parse(
        BigEndian::read_u16(&data[*offset..*offset+2])));
    *offset += 2;
    let mut ttl = BigEndian::read_u32(&data[*offset..*offset+4]);
    if ttl > i32::MAX as u32 {
        ttl = 0;
    }
    *offset += 4;
    let rdlen = BigEndian::read_u16(&data[*offset..*offset+2]) as usize;
    *offset += 2;
    if *offset + rdlen > data.len() {
        return Err(Error::UnexpectedEOF);
    }
    let data = try!(RRData::parse(typ,
        &data[*offset..*offset+rdlen], data));
    *offset += rdlen;
    Ok(ResourceRecord {
        name: name,
        cls: cls,
        ttl: ttl,
        data: data,
    })
}

// Function to parse an RFC 6891 OPT Pseudo RR
fn parse_opt_record<'a>(data: &'a [u8], offset: &mut usize) -> Result<OptRecord<'a>, Error> {
    *offset += 1;
    let typ = try!(Type::parse(
        BigEndian::read_u16(&data[*offset..*offset+2])));
    if typ != Type::OPT {
        return Err(Error::InvalidType(typ as u16));
    }
    *offset += 2;
    let udp = BigEndian::read_u16(&data[*offset..*offset+2]);
    *offset += 2;
    let extrcode = data[*offset];
    *offset += 1;
    let version = data[*offset];
    *offset += 1;
    let flags = BigEndian::read_u16(&data[*offset..*offset+2]);
    *offset += 2;
    let rdlen = BigEndian::read_u16(&data[*offset..*offset+2]) as usize;
    *offset += 2;
    if *offset + rdlen > data.len() {
        return Err(Error::UnexpectedEOF);
    }
    let data = try!(RRData::parse(typ,
        &data[*offset..*offset+rdlen], data));
    *offset += rdlen;

    Ok(OptRecord {
        udp: udp,
        extrcode: extrcode,
        version: version,
        flags: flags,
        data: data,
    })
}

#[cfg(test)]
mod test {

    use std::net::{Ipv4Addr, Ipv6Addr};
    use {Packet, Header};
    use Opcode::*;
    use ResponseCode::{NameError, NoError};
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
            authenticated_data: false,
            checking_disabled: false,
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
            authenticated_data: false,
            checking_disabled: false,
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
    fn parse_ns_response() {
        let response = b"\x4a\xf0\x81\x80\x00\x01\x00\x01\x00\x01\x00\x00\
                         \x03www\x05skype\x03com\x00\x00\x01\x00\x01\
                         \xc0\x0c\x00\x05\x00\x01\x00\x00\x0e\x10\
                         \x00\x1c\x07\x6c\x69\x76\x65\x63\x6d\x73\x0e\x74\
                         \x72\x61\x66\x66\x69\x63\x6d\x61\x6e\x61\x67\x65\
                         \x72\x03\x6e\x65\x74\x00\
                         \xc0\x42\x00\x02\x00\x01\x00\x01\xd5\xd3\x00\x11\
                         \x01\x67\x0c\x67\x74\x6c\x64\x2d\x73\x65\x72\x76\x65\x72\x73\
                         \xc0\x42";
         let packet = Packet::parse(response).unwrap();
         assert_eq!(packet.header, Header {
             id: 19184,
             query: false,
             opcode: StandardQuery,
             authoritative: false,
             truncated: false,
             recursion_desired: true,
             recursion_available: true,
             authenticated_data: false,
             checking_disabled: false,
             response_code: NoError,
             questions: 1,
             answers: 1,
             nameservers: 1,
             additional: 0,
         });
         assert_eq!(packet.questions.len(), 1);
         assert_eq!(packet.questions[0].qtype, QT::A);
         assert_eq!(packet.questions[0].qclass, QC::IN);
         assert_eq!(&packet.questions[0].qname.to_string()[..], "www.skype.com");
         assert_eq!(packet.answers.len(), 1);
         assert_eq!(&packet.answers[0].name.to_string()[..], "www.skype.com");
         assert_eq!(packet.answers[0].cls, C::IN);
         assert_eq!(packet.answers[0].ttl, 3600);
         match packet.answers[0].data {
             RRData::CNAME(cname) => {
                 assert_eq!(&cname.to_string()[..], "livecms.trafficmanager.net");
             }
             ref x => panic!("Wrong rdata {:?}", x),
         }
         assert_eq!(packet.nameservers.len(), 1);
         assert_eq!(&packet.nameservers[0].name.to_string()[..], "net");
         assert_eq!(packet.nameservers[0].cls, C::IN);
         assert_eq!(packet.nameservers[0].ttl, 120275);
         match packet.nameservers[0].data {
             RRData::NS(ns) => {
                 assert_eq!(&ns.to_string()[..], "g.gtld-servers.net");
             }
             ref x => panic!("Wrong rdata {:?}", x),
         }
     }

     #[test]
     fn parse_soa_response() {
         let response = b"\x9f\xc5\x85\x83\x00\x01\x00\x00\x00\x01\x00\x00\
                          \x0edlkfjkdjdslfkj\x07youtube\x03com\x00\x00\x01\x00\x01\
                          \xc0\x1b\x00\x06\x00\x01\x00\x00\x2a\x30\x00\x1e\xc0\x1b\
                          \x05admin\xc0\x1b\x77\xed\x2a\x73\x00\x00\x51\x80\x00\x00\
                          \x0e\x10\x00\x00\x3a\x80\x00\x00\x2a\x30";
          let packet = Packet::parse(response).unwrap();
          assert_eq!(packet.header, Header {
              id: 40901,
              query: false,
              opcode: StandardQuery,
              authoritative: true,
              truncated: false,
              recursion_desired: true,
              recursion_available: true,
              authenticated_data: false,
              checking_disabled: false,
              response_code: NameError,
              questions: 1,
              answers: 0,
              nameservers: 1,
              additional: 0,
          });
          assert_eq!(packet.questions.len(), 1);
          assert_eq!(packet.questions[0].qtype, QT::A);
          assert_eq!(packet.questions[0].qclass, QC::IN);
          assert_eq!(&packet.questions[0].qname.to_string()[..], "dlkfjkdjdslfkj.youtube.com");
          assert_eq!(packet.answers.len(), 0);

          assert_eq!(packet.nameservers.len(), 1);
          assert_eq!(&packet.nameservers[0].name.to_string()[..], "youtube.com");
          assert_eq!(packet.nameservers[0].cls, C::IN);
          assert_eq!(packet.nameservers[0].ttl, 10800);
          match packet.nameservers[0].data {
              RRData::SOA(ref soa_rec) => {
                assert_eq!(&soa_rec.primary_ns.to_string()[..], "youtube.com");
                assert_eq!(&soa_rec.mailbox.to_string()[..], "admin.youtube.com");
                assert_eq!(soa_rec.serial, 2012031603);
                assert_eq!(soa_rec.refresh, 20864);
                assert_eq!(soa_rec.retry, 3600);
                assert_eq!(soa_rec.expire, 14976);
                assert_eq!(soa_rec.minimum_ttl, 10800);
              }
              ref x => panic!("Wrong rdata {:?}", x),
          }
      }
      #[test]
      fn parse_ptr_response() {
          let response = b"\x53\xd6\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                           \x0269\x0293\x0275\x0272\x07in-addr\x04arpa\x00\
                           \x00\x0c\x00\x01\
                           \xc0\x0c\x00\x0c\x00\x01\x00\x01\x51\x80\x00\x1e\
                           \x10pool-72-75-93-69\x07verizon\x03net\x00";
          let packet = Packet::parse(response).unwrap();
          assert_eq!(packet.header, Header {
              id: 21462,
              query: false,
              opcode: StandardQuery,
              authoritative: false,
              truncated: false,
              recursion_desired: true,
              recursion_available: true,
              authenticated_data: false,
              checking_disabled: false,
              response_code: NoError,
              questions: 1,
              answers: 1,
              nameservers: 0,
              additional: 0,
          });
          assert_eq!(packet.questions.len(), 1);
          assert_eq!(packet.questions[0].qtype, QT::PTR);
          assert_eq!(packet.questions[0].qclass, QC::IN);
          assert_eq!(&packet.questions[0].qname.to_string()[..], "69.93.75.72.in-addr.arpa");
          assert_eq!(packet.answers.len(), 1);
          assert_eq!(&packet.answers[0].name.to_string()[..], "69.93.75.72.in-addr.arpa");
          assert_eq!(packet.answers[0].cls, C::IN);
          assert_eq!(packet.answers[0].ttl, 86400);
          match packet.answers[0].data {
              RRData::PTR(name) => {
                  assert_eq!(&name.to_string()[..], "pool-72-75-93-69.verizon.net");
              }
              ref x => panic!("Wrong rdata {:?}", x),
          }
      }

     #[test]
     fn parse_additional_record_response() {
         let response = b"\x4a\xf0\x81\x80\x00\x01\x00\x01\x00\x01\x00\x01\
                          \x03www\x05skype\x03com\x00\x00\x01\x00\x01\
                          \xc0\x0c\x00\x05\x00\x01\x00\x00\x0e\x10\
                          \x00\x1c\x07\x6c\x69\x76\x65\x63\x6d\x73\x0e\x74\
                          \x72\x61\x66\x66\x69\x63\x6d\x61\x6e\x61\x67\x65\
                          \x72\x03\x6e\x65\x74\x00\
                          \xc0\x42\x00\x02\x00\x01\x00\x01\xd5\xd3\x00\x11\
                          \x01\x67\x0c\x67\x74\x6c\x64\x2d\x73\x65\x72\x76\x65\x72\x73\
                          \xc0\x42\
                          \x01\x61\xc0\x55\x00\x01\x00\x01\x00\x00\xa3\x1c\
                          \x00\x04\xc0\x05\x06\x1e";
          let packet = Packet::parse(response).unwrap();
          assert_eq!(packet.header, Header {
              id: 19184,
              query: false,
              opcode: StandardQuery,
              authoritative: false,
              truncated: false,
              recursion_desired: true,
              recursion_available: true,
              authenticated_data: false,
              checking_disabled: false,
              response_code: NoError,
              questions: 1,
              answers: 1,
              nameservers: 1,
              additional: 1,
          });
          assert_eq!(packet.questions.len(), 1);
          assert_eq!(packet.questions[0].qtype, QT::A);
          assert_eq!(packet.questions[0].qclass, QC::IN);
          assert_eq!(&packet.questions[0].qname.to_string()[..], "www.skype.com");
          assert_eq!(packet.answers.len(), 1);
          assert_eq!(&packet.answers[0].name.to_string()[..], "www.skype.com");
          assert_eq!(packet.answers[0].cls, C::IN);
          assert_eq!(packet.answers[0].ttl, 3600);
          match packet.answers[0].data {
              RRData::CNAME(cname) => {
                  assert_eq!(&cname.to_string()[..], "livecms.trafficmanager.net");
              }
              ref x => panic!("Wrong rdata {:?}", x),
          }
          assert_eq!(packet.nameservers.len(), 1);
          assert_eq!(&packet.nameservers[0].name.to_string()[..], "net");
          assert_eq!(packet.nameservers[0].cls, C::IN);
          assert_eq!(packet.nameservers[0].ttl, 120275);
          match packet.nameservers[0].data {
              RRData::NS(ns) => {
                  assert_eq!(&ns.to_string()[..], "g.gtld-servers.net");
              }
              ref x => panic!("Wrong rdata {:?}", x),
          }
          assert_eq!(packet.additional.len(), 1);
          assert_eq!(&packet.additional[0].name.to_string()[..], "a.gtld-servers.net");
          assert_eq!(packet.additional[0].cls, C::IN);
          assert_eq!(packet.additional[0].ttl, 41756);
          match packet.additional[0].data {
              RRData::A(addr) => {
                  assert_eq!(addr, Ipv4Addr::new(192, 5, 6, 30));
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
            authenticated_data: false,
            checking_disabled: false,
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
            authenticated_data: false,
            checking_disabled: false,
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
            authenticated_data: false,
            checking_disabled: false,
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
            authenticated_data: false,
            checking_disabled: false,
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

    #[test]
    fn parse_aaaa_response() {
        let response = b"\xa9\xd9\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06\
            google\x03com\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\
            \x00\x8b\x00\x10*\x00\x14P@\t\x08\x12\x00\x00\x00\x00\x00\x00 \x0e";

        let packet = Packet::parse(response).unwrap();
        assert_eq!(packet.header, Header {
            id: 43481,
            query: false,
            opcode: StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authenticated_data: false,
            checking_disabled: false,
            response_code: NoError,
            questions: 1,
            answers: 1,
            nameservers: 0,
            additional: 0,
        });

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::AAAA);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "google.com");
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(&packet.answers[0].name.to_string()[..], "google.com");
        assert_eq!(packet.answers[0].cls, C::IN);
        assert_eq!(packet.answers[0].ttl, 139);
        match packet.answers[0].data {
            RRData::AAAA(addr) => {
                assert_eq!(addr, Ipv6Addr::new(
                    0x2A00, 0x1450, 0x4009, 0x812, 0, 0, 0, 0x200e)
                );
            }
            ref x => panic!("Wrong rdata {:?}", x),
        }
    }

    #[test]
    fn parse_cname_response() {
        let response = b"\xfc\x9d\x81\x80\x00\x01\x00\x06\x00\x02\x00\x02\x03\
            cdn\x07sstatic\x03net\x00\x00\x01\x00\x01\xc0\x0c\x00\x05\x00\x01\
            \x00\x00\x00f\x00\x02\xc0\x10\xc0\x10\x00\x01\x00\x01\x00\x00\x00\
            f\x00\x04h\x10g\xcc\xc0\x10\x00\x01\x00\x01\x00\x00\x00f\x00\x04h\
            \x10k\xcc\xc0\x10\x00\x01\x00\x01\x00\x00\x00f\x00\x04h\x10h\xcc\
            \xc0\x10\x00\x01\x00\x01\x00\x00\x00f\x00\x04h\x10j\xcc\xc0\x10\
            \x00\x01\x00\x01\x00\x00\x00f\x00\x04h\x10i\xcc\xc0\x10\x00\x02\
            \x00\x01\x00\x00\x99L\x00\x0b\x08cf-dns02\xc0\x10\xc0\x10\x00\x02\
            \x00\x01\x00\x00\x99L\x00\x0b\x08cf-dns01\xc0\x10\xc0\xa2\x00\x01\
            \x00\x01\x00\x00\x99L\x00\x04\xad\xf5:5\xc0\x8b\x00\x01\x00\x01\x00\
            \x00\x99L\x00\x04\xad\xf5;\x04";

        let packet = Packet::parse(response).unwrap();
        assert_eq!(packet.header, Header {
            id: 64669,
            query: false,
            opcode: StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authenticated_data: false,
            checking_disabled: false,
            response_code: NoError,
            questions: 1,
            answers: 6,
            nameservers: 2,
            additional: 2,
        });

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::A);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "cdn.sstatic.net");
        assert_eq!(packet.answers.len(), 6);
        assert_eq!(&packet.answers[0].name.to_string()[..], "cdn.sstatic.net");
        assert_eq!(packet.answers[0].cls, C::IN);
        assert_eq!(packet.answers[0].ttl, 102);
        match packet.answers[0].data {
            RRData::CNAME(cname) => {
                assert_eq!(&cname.to_string(), "sstatic.net");
            }
            ref x => panic!("Wrong rdata {:?}", x),
        }

        let ips = vec![
            Ipv4Addr::new(104, 16, 103, 204),
            Ipv4Addr::new(104, 16, 107, 204),
            Ipv4Addr::new(104, 16, 104, 204),
            Ipv4Addr::new(104, 16, 106, 204),
            Ipv4Addr::new(104, 16, 105, 204),
        ];
        for i in 1..6 {
            assert_eq!(&packet.answers[i].name.to_string()[..], "sstatic.net");
            assert_eq!(packet.answers[i].cls, C::IN);
            assert_eq!(packet.answers[i].ttl, 102);
            match packet.answers[i].data {
                RRData::A(addr) => {
                    assert_eq!(addr, ips[i-1]);
                }
                ref x => panic!("Wrong rdata {:?}", x),
            }
        }
    }

    #[test]
    fn parse_example_query_edns() {
        let query = b"\x95\xce\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\
            \x06google\x03com\x00\x00\x01\x00\
            \x01\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00";
        let packet = Packet::parse(query).unwrap();
        assert_eq!(packet.header, Header {
            id: 38350,
            query: true,
            opcode: StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: false,
            authenticated_data: false,
            checking_disabled: false,
            response_code: NoError,
            questions: 1,
            answers: 0,
            nameservers: 0,
            additional: 1,
        });
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::A);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "google.com");
        assert_eq!(packet.answers.len(), 0);
        match packet.opt {
            Some(opt) => {
                assert_eq!(opt.udp, 4096);
                assert_eq!(opt.extrcode, 0);
                assert_eq!(opt.version, 0);
                assert_eq!(opt.flags, 0);
            },
            None => panic!("Missing OPT RR")
        }
    }
}
