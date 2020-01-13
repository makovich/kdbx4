use crate::error::Error;
use crate::KdbxResult;

use log::*;

use chacha20::ChaCha20;
use salsa20::Salsa20;
use sha2::{Digest, Sha256, Sha512};
use stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};

use base64;

use pretty_hex::PrettyHex;

use std::fmt::{self, Debug};

/// Decrypted database has a form of XML.
/// This XML have fields marked as protected.
/// Those are BASE64 encoded data encrypted with a streaming cypher,
/// i.e. each next protected bytes encrypted right after another
/// without reinitializing ciphers IV.
pub enum StreamCipher {
    Salsa20(Vec<u8>),
    ChaCha20(Vec<u8>),
}

impl Debug for StreamCipher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "\n{}",
            match self {
                StreamCipher::Salsa20(v) => format!("Salsa20\n{:?}", v.hex_dump()),
                StreamCipher::ChaCha20(v) => format!("ChaCha20\n{:?}", v.hex_dump()),
            }
        )
    }
}

impl StreamCipher {
    pub fn try_from(id: u32, key: Vec<u8>) -> KdbxResult<StreamCipher> {
        use crate::constants::inner_header_type::*;

        match id {
            SALSA20_STREAM => Ok(StreamCipher::Salsa20(key)),
            CHACHA20_STREAM => Ok(StreamCipher::ChaCha20(key)),
            _ => Err(Error::UnsupportedStreamCipher(unsafe {
                ::std::mem::transmute::<u32, [u8; 4]>(id.to_le()).to_vec()
            })),
        }
    }

    /// Returns initialized `StreamDecryptor`.
    ///
    /// Returned instance must be used from the beginning to the end of XML database.
    ///
    /// # Example
    ///
    /// ```no_compile
    /// let cipher = StreamCipher::try_from(id, key).unwrap().decryptor();
    /// let protected = vec![u8_slice1, u8_slice2, u8_slice3].into_iter();
    /// let decrypted = protected.map(|v| cipher.decrypt(v).unwrap());
    /// ```
    ///
    pub fn decryptor(&self) -> StreamDecryptor {
        use crate::constants::SALSA20_IV;

        match self {
            StreamCipher::ChaCha20(stream_key) => {
                let mut h = Sha512::new();
                h.input(stream_key);
                let buf = h.result();

                let key = &buf[..32];
                let iv = &buf[32..44];

                StreamDecryptor(Box::new(
                    ChaCha20::new_var(key, iv).expect("Unable to create ChaCha20 decryptor"),
                ))
            }
            StreamCipher::Salsa20(stream_key) => {
                let mut h = Sha256::new();
                h.input(stream_key);
                let key = h.result();

                StreamDecryptor(Box::new(
                    Salsa20::new_var(&key, SALSA20_IV).expect("Unable to create Salsa20 decryptor"),
                ))
            }
        }
    }

    /// Decrypts a string with known offset of bytes
    /// starting from the first protected byte.
    pub fn decrypt_offset(&self, encrypted: &str, offset: usize) -> KdbxResult<String> {
        self.decryptor()
            .decrypt_offset(encrypted.as_bytes(), offset)
            .map(String::from_utf8)?
            .map_err(From::from)
    }
}

/// Helper to combine both needed traits
trait Encryptor: SyncStreamCipher + SyncStreamCipherSeek {}
impl<T: SyncStreamCipher + SyncStreamCipherSeek> Encryptor for T {}

pub struct StreamDecryptor(Box<dyn Encryptor>);

impl StreamDecryptor {
    #[allow(dead_code)]
    pub fn decrypt(&mut self, encrypted: &[u8]) -> KdbxResult<Vec<u8>> {
        self.decrypt_offset(encrypted, 0)
    }

    fn decrypt_offset(&mut self, encrypted: &[u8], skip: usize) -> KdbxResult<Vec<u8>> {
        let decoded = match base64::decode(&encrypted) {
            Ok(v) => v,
            Err(err) => {
                error!(
                    "unable to decode base64 value\n`{:?}`",
                    encrypted.hex_dump()
                );
                error!("cause: {:?}", err);
                return Err(Error::Decryption);
            }
        };

        debug!("BASE64\n{:?}", encrypted.hex_dump());
        debug!("DECODED\n{:?}", decoded.hex_dump());

        // How "inner random stream" decryption works:
        // - encrypt all zeroed array with particular cipher (pseudorandom stream)
        // - XOR each byte of the encrypted input with one from pseudorandom stream
        // - because of the streaming nature, the same decryptor instance
        //   must be used for all protected binary inputs (all Protected="Ture" fields
        //   within XML database document)
        let mut zero_buf = vec![0u8; decoded.len()];
        self.0.seek(skip as u64);
        self.0.apply_keystream(zero_buf.as_mut_slice());

        debug!("PSEUDORANDOM\n{:?}", zero_buf.hex_dump());

        Ok(zero_buf.iter().zip(decoded).map(|(x, y)| x ^ y).collect())
    }
}
