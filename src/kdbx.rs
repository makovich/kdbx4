use crate::database::{Binaries, Database, Xml};
use crate::encryption::{Cipher, Kdf, StreamCipher};
use crate::error::Error;
use crate::keys::{CompositeKey, TransformedKey};
use crate::Result as KdbxResult;

use log::*;

use byteorder::{ByteOrder, LE};

use hmac::{Hmac, Mac, NewMac};
use sha2::{Digest, Sha256};

use flate2::read::GzDecoder;

use pretty_hex::PrettyHex;

use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;

/// Opens KeePass KDBX4 database.
///
/// Use [`CompositeKey`] and [`open`] with `Path` to your database
/// or [`open_bytes`] with a reference to bytes already read beforehand.
///
/// [`CompositeKey`]: struct.CompositeKey.html
/// [`open`]: #method.open
/// [`open_bytes`]: #method.open_bytes
///
/// # Example
/// ```no_run
/// use kdbx4::{Kdbx4,CompositeKey};
///
/// let key = CompositeKey::new(Some("P@ssW0rd"), None::<String>).unwrap();
/// let db = Kdbx4::open("~/passwords.kdbx", key).unwrap();
///
/// assert!(db.entries().len() >= 0);
/// ```
#[derive(Debug)]
pub struct Kdbx4 {
    pub(super) master_seed: Vec<u8>,
    pub(super) kdf: Kdf,
    cipher: Cipher,
    gzip: bool,
}

impl Kdbx4 {
    /// Returns opened [`Database`] from `Path`.
    ///
    /// [`Database`]: struct.Database.html
    ///
    /// # Example
    /// ```no_run
    /// # use kdbx4::{Kdbx4,CompositeKey};
    /// # let key = CompositeKey::new(Some("P@ssW0rd"), None::<String>).unwrap();
    /// let db = Kdbx4::open("~/passwords.kdbx", key).unwrap();
    ///
    /// assert!(db.entries().len() >= 0);
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn open(file: impl AsRef<Path>, key: CompositeKey) -> KdbxResult<Database> {
        use std::fs::read;

        Kdbx4::open_bytes(read(file)?, key)
    }

    /// Returns opened [`Database`] reading it from provided bytes.
    ///
    /// [`Database`]: struct.Database.html
    ///
    /// # Example
    /// ```no_run
    /// # use std::io::prelude::*;
    /// # use std::net::TcpStream;
    /// # use kdbx4::{Kdbx4,CompositeKey};
    /// # let key = CompositeKey::new(Some("P@ssW0rd"), Some("~/.secret")).unwrap();
    /// let mut bytes = Vec::new();
    ///
    /// let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();
    /// stream.read_to_end(&mut bytes);
    ///
    /// let db = Kdbx4::open_bytes(bytes, key).unwrap();
    /// ```
    #[allow(clippy::needless_pass_by_value)]
    pub fn open_bytes(bytes: impl AsRef<[u8]>, key: CompositeKey) -> KdbxResult<Database> {
        parse(bytes.as_ref(), &key)
    }

    fn try_from(map: &HashMap<u8, &[u8]>) -> KdbxResult<Self> {
        use crate::constants::header_type::{
            CIPHER_ID, COMPRESSION_FLAGS, ENCRYPTION_IV, KDF_PARAMETERS, MASTER_SEED,
        };

        debug!("----- ({} fields) -----", {
            map.iter().for_each(debug_kv);
            map.len()
        });

        if ![
            &MASTER_SEED,
            &KDF_PARAMETERS,
            &CIPHER_ID,
            &ENCRYPTION_IV,
            &COMPRESSION_FLAGS,
        ]
        .iter()
        .all(|k| map.contains_key(k))
        {
            return Err(Error::BadFormat);
        }

        Ok(Kdbx4 {
            master_seed: map[&MASTER_SEED].to_vec(),
            kdf: Kdf::try_from(map[&KDF_PARAMETERS])?,
            cipher: Cipher::try_from(map[&CIPHER_ID], map[&ENCRYPTION_IV])?,
            gzip: map[&COMPRESSION_FLAGS].get(0).map_or(false, |v| v == &1),
        })
    }
}

fn parse(input: &[u8], key: &CompositeKey) -> KdbxResult<Database> {
    let mut offset = 0;

    verify_sig(&mut offset, input)?;
    let kdbx = read_header(&mut offset, input)?;
    debug!("{:?}", kdbx);

    let header = &input[..offset];
    let hash = read_bytes(&mut offset, input, 32);
    verify_sha(header, hash)?;

    Ok({
        let key = key.transform_with(&kdbx);
        let hash = read_bytes(&mut offset, input, 32);
        verify_hmac(header, hash, &key.header_key())?;

        let encrypted = read_encrypted_blocks(&mut offset, input, &key)?;
        let decripted = decrypt(&encrypted, &kdbx.cipher, &key, kdbx.gzip)?;

        let (cipher, bin, xml) = read_body(decripted)?;

        Database::new(cipher, xml, bin)?
    })
}

fn read_header(offset: &mut usize, input: &[u8]) -> KdbxResult<Kdbx4> {
    use crate::constants::header_type::END_OF_HEADER;

    let mut map = HashMap::new();

    loop {
        let (typ, _, val) = read_tlv(offset, input);

        if typ == END_OF_HEADER {
            return Ok(Kdbx4::try_from(&map)?);
        }

        map.insert(typ, val);
    }
}

fn read_encrypted_blocks(
    offset: &mut usize,
    input: &[u8],
    key: &TransformedKey,
) -> KdbxResult<Vec<u8>> {
    let mut blk_idx = 0;
    let mut blocks = Vec::new();

    while let Some((hmac, data)) = read_block(offset, input) {
        verify_block(data, hmac, blk_idx, &key.block_key(blk_idx))?;

        debug!("\nENCRYPTED BLOCK #{} ({} bytes)", blk_idx, data.len());

        blocks.extend_from_slice(data);
        blk_idx += 1;
    }

    Ok(blocks)
}

fn read_body(mut input: Vec<u8>) -> KdbxResult<(StreamCipher, Binaries, Xml)> {
    use crate::constants::inner_header_type::*;

    let mut offset = 0;

    let mut map = HashMap::new();
    let mut refs = Vec::new();

    loop {
        let (typ, len, val) = read_tlv(&mut offset, &input);

        if typ == BINARY {
            // Vec preserves natural KDBX-file binaries Ref="idx" ordering
            // First blob byte either BINARY_PROTECTED or - just skipping
            refs.push(Range {
                start: offset - len as usize + 1,
                end: offset,
            });

            continue;
        }

        if typ == END_OF_HEADER {
            break;
        }

        map.insert(typ, val.to_vec());
    }

    debug!("----- ({} fields) -----", {
        map.iter().for_each(debug_kv);
        map.len()
    });

    let cipher_id = LE::read_u32(map.get(&STREAM_ID).ok_or(Error::BadFormat)?);
    let cipher_key = map.remove(&STREAM_KEY).ok_or(Error::BadFormat)?;

    let cipher = StreamCipher::try_from(cipher_id, cipher_key)?;
    let xml = Xml::try_from(input.split_off(offset))?;
    let bin = Binaries::new(input, refs);

    Ok((cipher, bin, xml))
}

fn decrypt(
    encrypted: &[u8],
    cipher: &Cipher,
    key: &TransformedKey,
    decompress: bool,
) -> KdbxResult<Vec<u8>> {
    let res = cipher.decrypt(&encrypted, &key.final_key())?;

    Ok(if decompress { gunzip(&res)? } else { res })
}

fn gunzip(data: &[u8]) -> KdbxResult<Vec<u8>> {
    use std::io::Read;

    let mut dec = GzDecoder::new(data);
    let mut buf = Vec::new();
    dec.read_to_end(&mut buf)?;

    Ok(buf)
}

fn verify_sig<'a>(offset: &mut usize, input: &'a [u8]) -> KdbxResult<()> {
    use crate::constants::{SIG1, SIG2, VERSION};

    for exp in &[SIG1, SIG2, VERSION] {
        let fnd = &LE::read_u32(&input[*offset..]);

        debug!("SIGNATURE 0x{:X}", fnd);

        if fnd != exp {
            debug!("EXPECTED 0x{:X}", exp);

            return Err(Error::BadFormat);
        }

        *offset += 4;
    }

    Ok(())
}

fn verify_sha(header: &[u8], sha256: &[u8]) -> KdbxResult<()> {
    let mut hasher = Sha256::new();
    hasher.update(header);
    let digest = hasher.finalize();

    debug!(
        "\nHEADER SHA256\nSTORED {:?}\nDIGEST {:?}",
        sha256.hex_dump(),
        digest.as_slice().hex_dump()
    );

    if sha256 == digest.as_slice() {
        return Ok(());
    }

    Err(Error::CorruptedFile)
}

fn verify_hmac(header: &[u8], hmac256: &[u8], key: &[u8]) -> KdbxResult<()> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Error::Other("Can't verify HMAC".to_string()))?;

    hmac.update(header);

    if hmac.verify(hmac256).is_ok() {
        return Ok(());
    }

    let hmac = || {
        let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        hmac.update(header);
        hmac.finalize().into_bytes()
    };

    debug!(
        "\nHEADER HMAC256\nSTORED {:?}\nDIGEST {:?}",
        hmac256.hex_dump(),
        hmac().hex_dump()
    );

    Err(Error::CorruptedFile)
}

fn verify_block(data: &[u8], hmac256: &[u8], blk_idx: u64, key: &[u8]) -> KdbxResult<()> {
    let mut block_idx_bytes = [0; 8];
    LE::write_u64(&mut block_idx_bytes, blk_idx);

    let mut num_of_bytes = [0; 4];
    LE::write_u32(&mut num_of_bytes, data.len() as u32);

    let mut hmac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Error::Other("Can't verify HMAC".to_string()))?;

    hmac.update(&block_idx_bytes);
    hmac.update(&num_of_bytes);
    hmac.update(data);

    if hmac.verify(hmac256).is_ok() {
        return Ok(());
    }

    let hmac = || {
        let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        hmac.update(&block_idx_bytes);
        hmac.update(&num_of_bytes);
        hmac.update(data);
        hmac.finalize().into_bytes()
    };

    debug!(
        "\nHEADER HMAC256\nSTORED {:?}\nDIGEST {:?}",
        hmac256.hex_dump(),
        hmac().hex_dump()
    );

    Err(Error::CorruptedFile)
}

fn read_bytes<'a>(offset: &mut usize, input: &'a [u8], n: usize) -> &'a [u8] {
    let res = &input[*offset..*offset + n];
    *offset += n;
    res
}

fn read_tlv<'a>(offset: &mut usize, input: &'a [u8]) -> (u8, u32, &'a [u8]) {
    let typ = input[*offset];
    let len = LE::read_u32(&input[*offset + 1..]);
    let end_len = *offset + 5 + len as usize;
    let val = &input[*offset + 5..end_len];

    *offset = end_len;

    (typ, len, val)
}

fn read_block<'a>(offset: &mut usize, input: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
    let hmac256 = &input[*offset..*offset + 32];
    let len = LE::read_u32(&input[*offset + 32..]) as usize;

    if len == 0 {
        *offset += 32 + 4;
        return None;
    }

    let end_len = *offset + 32 + 4 + len;
    let data = &input[*offset + 32 + 4..end_len];

    *offset += 32 + 4 + len;

    Some((hmac256, data))
}

#[allow(clippy::needless_pass_by_value)]
fn debug_kv(kv: (&u8, impl AsRef<[u8]>)) {
    debug!("\nField '0x{:X}' {:?}", kv.0, kv.1.as_ref().hex_dump())
}
