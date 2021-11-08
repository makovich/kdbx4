use crate::constants::inner_header_type::*;
use crate::error::Error;
use crate::Result as KdbxResult;

use log::*;

use chacha20::ChaCha20;
use salsa20::Salsa20;
use sha2::{Digest, Sha256, Sha512};

use pretty_hex::PrettyHex;

use std::fmt::{self, Debug};

/// Decrypted database has a form of XML.
/// This XML have fields marked as protected.
/// Those are BASE64 encoded data encrypted with a streaming cypher,
/// i.e. each next protected bytes encrypted right after another
/// without reinitializing ciphers IV.
pub struct StreamCipher {
    id: u32,
    key: Vec<u8>,
}

impl Debug for StreamCipher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "\n{}",
            match self.id {
                SALSA20_STREAM => format!("Salsa20\n{:?}", self.key.hex_dump()),
                CHACHA20_STREAM => format!("ChaCha20\n{:?}", self.key.hex_dump()),
                _ => format!(
                    "Unknown stream cipher: id={:?}!\n{:?}",
                    self.id.to_le_bytes(),
                    self.key.hex_dump()
                ),
            }
        )
    }
}

impl StreamCipher {
    pub fn try_from(id: u32, key: Vec<u8>) -> KdbxResult<StreamCipher> {
        let supported = [SALSA20_STREAM, CHACHA20_STREAM];

        if supported.contains(&id) {
            return Ok(StreamCipher { id, key });
        }

        Err(Error::UnsupportedStreamCipher(id.to_le_bytes().to_vec()))
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
    pub fn decryptor(&self) -> Decryptor {
        use crate::constants::SALSA20_IV;
        use cipher::NewCipher;

        match self.id {
            SALSA20_STREAM => {
                let mut h = Sha256::new();
                h.update(&self.key);
                let key = h.finalize();

                Decryptor::Salsa20(Box::new(
                    Salsa20::new_from_slices(&key, SALSA20_IV)
                        .expect("Unable to create Salsa20 decryptor"),
                ))
            }
            CHACHA20_STREAM => {
                let mut h = Sha512::new();
                h.update(&self.key);
                let buf = h.finalize();

                let key = &buf[..32];
                let iv = &buf[32..44];

                Decryptor::ChaCha20(Box::new(
                    ChaCha20::new_from_slices(key, iv)
                        .expect("Unable to create ChaCha20 decryptor"),
                ))
            }
            _ => unreachable!(),
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

pub enum Decryptor {
    Salsa20(Box<salsa20::Salsa20>),
    ChaCha20(Box<chacha20::ChaCha20>),
}

impl Decryptor {
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

        match self {
            Decryptor::Salsa20(cipher) => {
                apply_keystream(cipher.as_mut(), skip as u64, zero_buf.as_mut_slice())
            }

            Decryptor::ChaCha20(cipher) => {
                apply_keystream(cipher.as_mut(), skip as u64, zero_buf.as_mut_slice())
            }
        }

        debug!("PSEUDORANDOM\n{:?}", zero_buf.hex_dump());

        Ok(zero_buf.iter().zip(decoded).map(|(x, y)| x ^ y).collect())
    }
}

fn apply_keystream<C>(cipher: &mut C, skip: u64, buf: &mut [u8])
where
    C: cipher::StreamCipher + cipher::StreamCipherSeek,
{
    cipher.seek(skip);
    cipher.apply_keystream(buf);
}
