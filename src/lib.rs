extern crate byteorder;
#[macro_use] extern crate matches;
#[macro_use(quick_error)] extern crate quick_error;

mod enums;
mod structs;
mod name;
mod parser;
mod error;
mod header;
mod rrdata;
mod builder;

pub use enums::{Type, QueryType, Class, QueryClass, ResponseCode, Opcode};
pub use structs::{Question, ResourceRecord, OptRecord, Packet, SoaRecord};
pub use name::{Name};
pub use error::{Error};
pub use header::{Header};
pub use rrdata::{RRData};
pub use builder::{Builder};
