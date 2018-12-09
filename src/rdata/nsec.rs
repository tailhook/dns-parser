#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Record;

impl super::RecordType for Record {
    const TYPE: isize = 47;
}
impl<'a> super::Record<'a> for Record {

    fn parse(_rdata: &'a [u8], _original: &'a [u8]) -> super::RDataResult<'a> {
        unimplemented!();
    }
}
