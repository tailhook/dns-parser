extern crate byteorder;
#[macro_use] extern crate quick_error;

mod enums;
mod structs;
mod name;
mod parser;
mod error;
mod header;

pub use enums::{Type, QueryType, Class, QueryClass, ResponseCode, Opcode};
pub use structs::{Question, ResourceRecord};
pub use name::{Name};
pub use error::{Error};
pub use header::{Header};

