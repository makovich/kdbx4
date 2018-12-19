use crate::error::Error;
use crate::KdbxResult;

use log::*;

use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::chacha20::ChaCha20;
use crypto::digest::Digest;
use crypto::salsa20::Salsa20;
use crypto::sha2::{Sha256, Sha512};
use crypto::symmetriccipher::Encryptor;

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
    /// let cipher = StreamCipher::ChaCha20(key);
    /// let protected = vec![u8_slice1, u8_slice2, u8_slice3].into_iter();
    /// let decrypted = protected.map(|v| cipher.decrypt(v).unwrap());
    /// ```
    ///
    pub fn decryptor(&self) -> StreamDecryptor {
        use crate::constants::SALSA20_IV;

        match self {
            StreamCipher::ChaCha20(stream_key) => {
                let mut buf = [0; 64];
                let mut h = Sha512::new();
                h.input(stream_key);
                h.result(&mut buf);

                let key = &buf[..32];
                let iv = &buf[32..44];

                StreamDecryptor(Box::new(ChaCha20::new(key, iv)))
            }
            StreamCipher::Salsa20(stream_key) => {
                let mut key = [0; 32];
                let mut h = Sha256::new();
                h.input(stream_key);
                h.result(&mut key);

                StreamDecryptor(Box::new(Salsa20::new(&key, SALSA20_IV)))
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

pub struct StreamDecryptor(Box<Encryptor>);

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

        let mut pseudorandom = Vec::<u8>::new();

        // How inner random stream decrypting works:
        // - encrypt all zeroed array with particular cipher
        // - XOR each byte of the encrypted input with previously generated
        //   pseudorandom stream's byte
        // - because of the streaming nature, the same decryptor instance
        //   must be used for all protected binary inputs
        //   (think of concatenation of all passwords apperaing in a document order)
        {
            let zero_buf = vec![0u8; skip + decoded.len()];
            let mut read_buf = RefReadBuffer::new(&zero_buf);

            let mut buf = vec![0u8; skip + decoded.len()];
            let mut write_buf = RefWriteBuffer::new(&mut buf);

            loop {
                let op = self.0.encrypt(&mut read_buf, &mut write_buf, true);

                pseudorandom.extend_from_slice(write_buf.take_read_buffer().take_remaining());

                match op {
                    Ok(BufferResult::BufferUnderflow) => break,
                    Ok(BufferResult::BufferOverflow) => { /* print!("*") */ }
                    Err(err) => {
                        error!("cause: {:?}", err);
                        return Err(Error::Decryption);
                    }
                }
            }
        }

        debug!(
            "PSEUDORANDOM\n{:?}",
            pseudorandom[skip..(skip + decoded.len())]
                .as_ref()
                .hex_dump()
        );

        Ok(pseudorandom[skip..]
            .iter()
            .zip(decoded)
            .map(|(x, y)| x ^ y)
            .collect())
    }
}
