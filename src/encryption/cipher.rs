use crate::error::Error;
use crate::KdbxResult;

use log::*;

use crypto::aes::{cbc_decryptor, KeySize};
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::chacha20::ChaCha20;
use crypto::symmetriccipher::Decryptor;

#[derive(Debug)]
pub enum Cipher {
    ChaCha20([u8; 12]),
    Aes256([u8; 16]),
}

impl Cipher {
    pub fn try_from(cipher_id: &[u8], enc_iv: &[u8]) -> KdbxResult<Self> {
        use crate::constants::uuid::{AES256, CHACHA20};

        match cipher_id {
            CHACHA20 => {
                let mut ary = [0; 12];
                ary.copy_from_slice(enc_iv);
                Ok(Cipher::ChaCha20(ary))
            }
            AES256 => {
                let mut ary = [0; 16];
                ary.copy_from_slice(enc_iv);
                Ok(Cipher::Aes256(ary))
            }
            _ => Err(Error::UnsupportedCipher(cipher_id.to_vec())),
        }
    }

    pub fn decrypt(&self, encrypted: &[u8], key: &[u8]) -> KdbxResult<Vec<u8>> {
        let mut decryptor = self.create_decryptor(key);
        let mut res = Vec::new();
        let mut buf = [0u8; 4 * 1024];
        let mut write_buf = RefWriteBuffer::new(&mut buf);
        let mut read_buf = RefReadBuffer::new(&encrypted);

        loop {
            let op = decryptor.decrypt(&mut read_buf, &mut write_buf, true);

            res.extend_from_slice(write_buf.take_read_buffer().take_remaining());

            match op {
                Ok(BufferResult::BufferUnderflow) => break,
                Ok(BufferResult::BufferOverflow) => { /* print!("*") */ }
                Err(err) => {
                    error!("cause: {:?}", err);
                    return Err(Error::Decryption);
                }
            }
        }

        Ok(res)
    }

    fn create_decryptor(&self, key: &[u8]) -> Box<Decryptor> {
        match self {
            Cipher::ChaCha20(iv) => Box::new(ChaCha20::new(key, iv)),
            Cipher::Aes256(iv) => cbc_decryptor(KeySize::KeySize256, key, iv, PkcsPadding),
        }
    }
}
