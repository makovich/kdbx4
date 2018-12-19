use crate::kdbx::Kdbx4;

use byteorder::{ByteOrder, LE};

use crypto::digest::Digest;
use crypto::sha2::{Sha256, Sha512};

use std::fs::read;
use std::io;
use std::path::Path;

/// The key to the database.
///
/// May be constructed with a plain password string
/// or from a password and a key file ([read more](https://keepass.info/help/base/keys.html)).
pub struct CompositeKey {
    keys: Vec<[u8; 32]>,
}

impl CompositeKey {
    /// Creates `CompositeKey` using master password and database key file. Both arguments are optional.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn main() -> std::io::Result<()> {
    /// use kdbx4::{Kdbx4,CompositeKey};
    ///
    /// let key = CompositeKey::new(None, Some("~/.secret"))?;
    /// let db = Kdbx4::open("~/passwords.kdbx", key);
    /// #   Ok(())
    /// # }
    /// ```
    ///
    #[allow(clippy::new_ret_no_self)]
    pub fn new<F>(password: Option<&str>, key_file: Option<F>) -> Result<Self, io::Error>
    where
        F: AsRef<Path>,
    {
        let mut keys = Vec::with_capacity(3);

        if let Some(pass) = password {
            keys.push(hash(pass.as_bytes()))
        }

        if let Some(key_file) = key_file {
            keys.push(hash(&read(key_file)?))
        }

        Ok(CompositeKey { keys })
    }

    /// Runs KDF transformation for `CompositeKey`.
    pub(super) fn transform_with<'a>(&self, kdbx: &'a Kdbx4) -> TransformedKey<'a> {
        let transformed_key = kdbx.kdf.transform(&self.compose_keys());

        TransformedKey(transformed_key, kdbx)
    }

    fn compose_keys(&self) -> [u8; 32] {
        let mut composite_key = [0; 32];
        let mut h = Sha256::new();
        self.keys.iter().for_each(|k| h.input(k));
        h.result(&mut composite_key);

        composite_key
    }
}

/// The key after key derivation function applied.
/// Speeds up forming of various sub keys in a database.
pub struct TransformedKey<'a>(Vec<u8>, &'a Kdbx4);

impl<'a> TransformedKey<'a> {
    pub fn header_key(&self) -> [u8; 64] {
        use crate::constants;

        self.block_key(constants::HEADER_BLK_IDX)
    }

    pub fn block_key(&self, block_idx: u64) -> [u8; 64] {
        let mut block_idx_bytes = [0; 8];
        LE::write_u64(&mut block_idx_bytes, block_idx);

        let mut block_key = [0; 64];
        let mut h = Sha512::new();
        h.input(&block_idx_bytes);
        h.input(&self.hmac_key());
        h.result(&mut block_key);

        block_key
    }

    pub fn hmac_key(&self) -> [u8; 64] {
        let mut hmac_key = [0; 64];
        let mut h = Sha512::new();
        h.input(&self.1.master_seed);
        h.input(&self.0);
        h.input(&[1]);
        h.result(&mut hmac_key);

        hmac_key
    }

    pub fn final_key(&self) -> [u8; 32] {
        let mut final_key = [0; 32];
        let mut h = Sha256::new();
        h.input(&self.1.master_seed);
        h.input(&self.0);
        h.result(&mut final_key);

        final_key
    }
}

fn hash(slice: &[u8]) -> [u8; 32] {
    let mut hash = [0; 32];
    let mut h = Sha256::new();
    h.input(slice);
    h.result(&mut hash);

    hash
}
