use log::*;

use xmlparser;

use pretty_hex::PrettyHex;

use std::error;
use std::fmt;
use std::io;
use std::string;

#[derive(Debug)]
pub enum Error {
    /// Unknown database cipher UUID.
    /// Only `ChaCha20` and `AES256` are supported.
    UnsupportedCipher(Vec<u8>),

    /// Unknown key derivation function UUID.
    /// Only `Argon2` and `AES` are supported.
    UnsupportedKdf(Vec<u8>),

    /// Unknown cipher for the inner stream (i.e. data encrypted within XML).
    /// Only `ChaCha20` and `Salsa20` are supported.
    UnsupportedStreamCipher(Vec<u8>),

    /// Error during file decryption (see log output for more info).
    Decryption,

    /// Error during parsing XML.
    XmlParse,

    /// Malformed KDBX4 file or unsupported features (see log output for more info).
    BadFormat,

    /// Wrong password, key file or corrupted file.
    CorruptedFile,

    Io(io::Error),
    Other(String),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<xmlparser::Error> for Error {
    fn from(err: xmlparser::Error) -> Self {
        error!("unable to parse xml\n{}", err);
        Error::XmlParse
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Self {
        error!(
            "unable to convert to a string\n{}",
            err.as_bytes().hex_dump()
        );
        Error::Decryption
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error::Other(err)
    }
}

impl<'a> From<&'a str> for Error {
    fn from(err: &'a str) -> Error {
        Error::Other(err.to_owned())
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        if let Error::Io(ref e) = self {
            Some(e)
        } else {
            None
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnsupportedCipher(ref u) => {
                write!(f, "Unsupported cipher (UUID: {})", u.hex_dump())
            }
            Error::UnsupportedKdf(ref u) => write!(f, "Unsupported KDF (UUID: {})", u.hex_dump()),
            Error::UnsupportedStreamCipher(ref u) => {
                write!(f, "Unsupported stream cipher (UUID: {})", u.hex_dump())
            }
            Error::Decryption => write!(f, "Unable to decrypt database"),
            Error::XmlParse => write!(f, "Unable to parse XML"),
            Error::BadFormat => write!(f, "Unsupported database file format"),
            Error::CorruptedFile => write!(f, "Database file corrupted or wrong key"),
            Error::Io(ref e) => e.fmt(f),
            Error::Other(ref s) => f.write_str(&**s),
        }
    }
}
