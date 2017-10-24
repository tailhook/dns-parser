use std::str;

use Error;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Record(pub String);

impl<'a> super::Record<'a> for Record {

    const TYPE: isize = 16;

    fn parse(rdata: &'a [u8], _original: &'a [u8]) -> super::RDataResult<'a> {
        let len = rdata.len();
        if len < 1 {
            return Err(Error::WrongRdataLength);
        }
        let mut ret_string = String::new();
        let mut pos = 0;
        while pos < len {
            let rdlen = rdata[pos] as usize;
            pos += 1;
            if len < rdlen + pos {
                return Err(Error::WrongRdataLength);
            }
            match str::from_utf8(&rdata[pos..(pos+rdlen)]) {
                Ok(val) => ret_string.push_str(val),
                Err(e) => return Err(Error::TxtDataIsNotUTF8(e)),
            }
            pos += rdlen;
        }
        Ok(super::RData::TXT(Record(ret_string)))
    }
}

#[cfg(test)]
mod test {

    use {Packet, Header};
    use Opcode::*;
    use ResponseCode::NoError;
    use QueryType as QT;
    use QueryClass as QC;
    use Class as C;
    use RData;

    #[test]
    fn parse_response_multiple_strings() {
        let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                          \x08facebook\x03com\x00\x00\x10\x00\x01\
                          \xc0\x0c\x00\x10\x00\x01\x00\x01\x51\x3d\x00\x23\
                          \x15\x76\x3d\x73\x70\x66\x31\x20\x72\x65\x64\x69\
                          \x72\x65\x63\x74\x3d\x5f\x73\x70\x66\x2e\
                          \x0c\x66\x61\x63\x65\x62\x6f\x6f\x6b\x2e\x63\x6f\x6d";

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
        assert_eq!(packet.questions[0].qtype, QT::TXT);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "facebook.com");
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(&packet.answers[0].name.to_string()[..], "facebook.com");
        assert_eq!(packet.answers[0].multicast_unique, false);
        assert_eq!(packet.answers[0].cls, C::IN);
        assert_eq!(packet.answers[0].ttl, 86333);
        match packet.answers[0].data {
            RData::TXT(ref text) => {
                assert_eq!(text.0, "v=spf1 redirect=_spf.facebook.com")
            }
            ref x => panic!("Wrong rdata {:?}", x),
        }
    }
}
