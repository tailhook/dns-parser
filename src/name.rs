use std::fmt;
use std::fmt::Write;
use std::str::from_utf8;
use std::ascii::AsciiExt;

use byteorder::{BigEndian, ByteOrder};

use {Error};

#[derive(Debug)]
pub struct Name<'a>{
    labels: &'a [u8],
    /// This is the original buffer size. The compressed names in original
    /// are calculated in this buffer
    original: &'a [u8],
}

impl<'a> Name<'a> {
    pub fn scan(data: &'a[u8], original: &'a[u8]) -> Result<Name<'a>, Error> {
        let mut pos = 0;
        loop {
            if data.len() <= pos {
                return Err(Error::UnexpectedEOF);
            }
            let byte = data[pos];
            if byte == 0 {
                return Ok(Name { labels: &data[..pos+1], original: data });
            } else if byte & 0b1100_0000 == 0b1100_0000 {
                if data.len() < pos+2 {
                    return Err(Error::UnexpectedEOF);
                }
                let off = (BigEndian::read_u16(&data[pos..pos+2])
                           & !0b1100_0000_0000_0000) as usize;
                if off >= original.len() {
                    return Err(Error::UnexpectedEOF);
                }
                // Validate referred to location
                try!(Name::scan(&original[off..], original));
                return Ok(Name { labels: &data[..pos+2], original: data });
            } else if byte & 0b1100_0000 == 0 {
                let end = pos + byte as usize + 1;
                if !data[pos+1..end].is_ascii() {
                    return Err(Error::LabelIsNotAscii);
                }
                pos = end;
                if data.len() <= pos {
                    return Err(Error::UnexpectedEOF);
                }
                continue;
            } else {
                return Err(Error::UnknownLabelFormat);
            }
        }
    }
    pub fn byte_len(&self) -> usize {
        self.labels.len()
    }
}

impl<'a> fmt::Display for Name<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let data = self.labels;
        let original = self.original;
        let mut pos = 0;
        loop {
            let byte = data[pos];
            if byte == 0 {
                return Ok(());
            } else if byte & 0b1100_0000 == 0b1100_0000 {
                let off = (BigEndian::read_u16(&data[pos..pos+2])
                           & !0b1100_0000_0000_0000) as usize;
                return fmt::Display::fmt(
                    &Name::scan(&original[off..], original).unwrap(), fmt)
            } else if byte & 0b1100_0000 == 0 {
                if pos != 0 {
                    try!(fmt.write_char('.'));
                }
                let end = pos + byte as usize + 1;
                try!(fmt.write_str(from_utf8(&data[pos+1..end]).unwrap()));
                pos = end;
                continue;
            } else {
                unreachable!();
            }
        }
    }
}
