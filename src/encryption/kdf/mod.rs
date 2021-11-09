mod aes;
mod argon2;

use crate::error::Error;
use crate::Result as KdbxResult;

use log::*;

use byteorder::{ByteOrder, LE};
use pretty_hex::PrettyHex;

use std::collections::HashMap;

#[derive(Debug)]
pub enum Kdf {
    Argon2d { params: argon2::Params },
    Argon2id { params: argon2::Params },
    Aes { seed: Vec<u8>, rounds: u64 },
}

impl Kdf {
    pub fn transform(&self, key: &[u8]) -> Vec<u8> {
        match self {
            Kdf::Argon2d { params } => argon2::transform_d(key, params),
            Kdf::Argon2id { params } => argon2::transform_id(key, params),
            Kdf::Aes { seed, rounds } => aes::transform(key, seed, *rounds),
        }
    }

    pub fn try_from(input: &[u8]) -> KdbxResult<Self> {
        use crate::constants::{
            uuid::{AES_KDF, ARGON2D_KDF, ARGON2ID_KDF},
            vd_param::{aes::*, UUID},
            vd_type::NONE,
            EMPTY, VD_VER,
        };

        let mut map = HashMap::new();

        if VD_VER != LE::read_u16(input) {
            error!(
                "Unsupported Variable Dictionary version\n{:?}",
                input[..2].as_ref().hex_dump()
            );
            return Err(Error::BadFormat);
        }

        let mut offset = 2;

        loop {
            let (typ, key, val) = read_kv(&mut offset, input);

            if typ == NONE {
                break;
            }

            map.insert(key, val);
        }

        debug!("----- ({} fields) -----", {
            map.iter().for_each(debug_kv);
            map.len()
        });

        match map.get(UUID) {
            Some(&ARGON2D_KDF) => Ok(Kdf::Argon2d {
                params: make_params(&map),
            }),
            Some(&ARGON2ID_KDF) => Ok(Kdf::Argon2id {
                params: make_params(&map),
            }),
            Some(&AES_KDF) => Ok(Kdf::Aes {
                seed: map.get(SEED).unwrap_or(&EMPTY).to_vec(),
                rounds: LE::read_u64(map.get(ROUNDS).unwrap_or(&DEFAULT_ROUNDS)),
            }),
            Some(kdf) => Err(Error::UnsupportedKdf(kdf.to_vec())),
            _ => {
                error!("Could not find KDF UUID field in the header");
                Err(Error::BadFormat)
            }
        }
    }
}

fn read_kv<'a>(offset: &mut usize, input: &'a [u8]) -> (u8, &'a str, &'a [u8]) {
    let (&typ, rest) = input[*offset..].split_first().unwrap();

    if rest.is_empty() {
        return (0, "", &[]);
    }

    let key_len = LE::read_u32(rest) as usize;
    let key = &rest[4..(4 + key_len)];
    let key = ::std::str::from_utf8(key).unwrap();

    let (_, rest) = rest.split_at(4 + key_len);

    let val_len = LE::read_u32(rest) as usize;
    let val = &rest[4..(4 + val_len)];

    *offset += 1 /* typ */ + 4 + key_len + 4 + val_len;

    (typ, key, val)
}

fn debug_kv(kv: (&&str, &&[u8])) {
    debug!("\nField '{}' {:?}", kv.0, kv.1.hex_dump())
}

fn make_params(map: &HashMap<&str, &[u8]>) -> argon2::Params {
    use crate::constants::{vd_param::argon2::*, EMPTY};

    let iterations = LE::read_u64(map.get(ITERATIONS).unwrap_or(&DEFAULT_ITERATIONS)) as u32;
    let parallelism = LE::read_u32(map.get(PARALLELISM).unwrap_or(&DEFAULT_PARALLELISM));
    let memory = LE::read_u64(map.get(MEMORY).unwrap_or(&DEFAULT_MEMORY)) as u32;
    let salt = map.get(SALT).unwrap_or(&EMPTY).to_vec();
    let secret_key = map.get(SECRETKEY).unwrap_or(&EMPTY).to_vec();
    let assoc_data = map.get(ASSOCDATA).unwrap_or(&EMPTY).to_vec();

    argon2::Params {
        iterations,
        parallelism,
        memory,
        salt,
        secret_key,
        assoc_data,
    }
}
