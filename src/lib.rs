//! This is an implementation of KeePass database file reader in Rust.
//! This crate aims to work with [KDBX version 4](https://keepass.info/help/kb/kdbx_4.html) format.
mod constants;
mod database;
mod encryption;
mod error;
mod kdbx;
mod keys;

pub use crate::database::*;
pub use crate::error::Error;
pub use crate::kdbx::Kdbx4;
pub use crate::keys::CompositeKey;

pub type Result<T> = ::std::result::Result<T, error::Error>;
