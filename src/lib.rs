#![recursion_limit="100"]
//! The network-agnostic DNS parser library
//!
//! [Documentation](https://docs.rs/dns-parser) |
//! [Github](https://github.com/tailhook/dns-parser) |
//! [Crate](https://crates.io/crates/dns-parser)
//!
//! Use [`Builder`] to create a new outgoing packet.
//!
//! Use [`Packet::parse`] to parse a packet into a data structure.
//!
//! [`Builder`]: struct.Builder.html
//! [`Packet::parse`]: struct.Packet.html#method.parse
//!
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

extern crate byteorder;
#[cfg(test)] #[macro_use] extern crate matches;
#[macro_use(quick_error)] extern crate quick_error;

mod enums;
mod structs;
mod name;
mod parser;
mod error;
mod header;
mod builder;

/// Data types and methods for handling the RData field
#[allow(missing_docs)] // resource records are pretty self-descriptive
pub mod rdata;

pub use enums::{Class, QueryClass, ResponseCode, Opcode};
pub use structs::{Question, ResourceRecord, Packet};
pub use name::{Name};
pub use error::{Error};
pub use header::{Header};
pub use rdata::{Type, QueryType, RData};
pub use builder::{Builder};
