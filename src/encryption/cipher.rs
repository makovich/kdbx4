use crate::error::Error;
use crate::Result as KdbxResult;

use log::*;

use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use chacha20::ChaCha20;
use cipher::{NewCipher, StreamCipher};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

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
        match self {
            Cipher::ChaCha20(iv) => {
                debug!("decrypting ChaCha20");

                let mut res = encrypted.to_owned();
                ChaCha20::new(key.into(), iv.into()).apply_keystream(res.as_mut());
                Ok(res)
            }
            Cipher::Aes256(iv) => {
                debug!("decrypting Aes256");

                Aes256Cbc::new_fix(key.into(), iv.into())
                    .decrypt_vec(encrypted)
                    .map_err(|_| Error::Decryption)
            }
        }
    }
}
