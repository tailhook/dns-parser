use std::fmt;
use std::fmt::Write;
use std::str::from_utf8;
use std::ascii::AsciiExt;

use byteorder::{BigEndian, ByteOrder};

use {Error};

/// The DNS name as stored in the original packet
///
/// This is contains just a reference to a slice that contains the data.
/// You may turn this into a string using `.to_string()`
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Name<'a>{
    labels: &'a [u8],
    /// This is the original buffer size. The compressed names in original
    /// are calculated in this buffer
    original: &'a [u8],
}

impl<'a> Name<'a> {
    pub fn scan(data: &'a[u8], original: &'a[u8]) -> Result<Name<'a>, Error> {
        let mut parse_data = data;
        let mut return_pos = None;
        let mut pos = 0;
        if parse_data.len() <= pos {
            return Err(Error::UnexpectedEOF);
        }
        // By setting the largest_pos to be the original len, a side effect is that the pos
        // variable can move forwards in the buffer once.
        let mut largest_pos = original.len();
        let mut byte = parse_data[pos];
        while byte != 0 {
            if parse_data.len() <= pos {
                return Err(Error::UnexpectedEOF);
            }
            if byte & 0b1100_0000 == 0b1100_0000 {
                if parse_data.len() < pos+2 {
                    return Err(Error::UnexpectedEOF);
                }
                let off = (BigEndian::read_u16(&parse_data[pos..pos+2])
                           & !0b1100_0000_0000_0000) as usize;
                if off >= original.len() {
                    return Err(Error::UnexpectedEOF);
                }
                // Set the value for return_pos which is the pos in the original data buffer
                // that should be used to return after validating the offsetted labels.
                if let None = return_pos {
                    return_pos = Some(pos);
                }

                // Check then set largest_pos to ensure we never go backwards in the buffer.
                if off >= largest_pos {
                    return Err(Error::BadPointer);
                }
                largest_pos = off;
                pos = 0;
                parse_data = &original[off..];
            } else if byte & 0b1100_0000 == 0 {
                let end = pos + byte as usize + 1;
                if parse_data.len() < end {
                    return Err(Error::UnexpectedEOF);
                }
                if !parse_data[pos+1..end].is_ascii() {
                    return Err(Error::LabelIsNotAscii);
                }
                pos = end;
                if parse_data.len() <= pos {
                    return Err(Error::UnexpectedEOF);
                }
            } else {
                return Err(Error::UnknownLabelFormat);
            }
            byte = parse_data[pos];
        }
        if let Some(return_pos) = return_pos {
            return Ok(Name { labels: &data[..return_pos+2], original: original });
        } else {
            return Ok(Name { labels: &data[..pos+1], original: original });
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
                if pos != 0 {
                    try!(fmt.write_char('.'));
                }
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

#[cfg(test)]
mod test {
    use Error;
    use Name;

    #[test]
    fn parse_badpointer_same_offset() {
        // A buffer where an offset points to itself, a bad compression pointer.
        let buffer_same_offset = vec![192, 2, 192, 2];

        assert_eq!(Name::scan(&buffer_same_offset, &buffer_same_offset), Err(Error::BadPointer));
    }

    #[test]
    fn parse_badpointer_forward_offset() {
        // A buffer where the offsets points back to each other which would cause infinite recursion
        // if never checked, a bad compression pointer.
        let buffer_forwards_offset = vec![192, 2, 192, 4, 192, 2];

        assert_eq!(Name::scan(&buffer_forwards_offset, &buffer_forwards_offset), Err(Error::BadPointer));
    }
}
