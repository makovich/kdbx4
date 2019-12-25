use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes256;
use sha2::{Digest, Sha256};

use std::sync::Arc;
use std::thread;

pub(super) fn transform(key_to_derive: &[u8], enc_key: &[u8], rounds: u64) -> Vec<u8> {
    let mut derived = [0; 32];
    let mut left = [0; 16];
    let mut right = [0; 16];

    left.copy_from_slice(&key_to_derive[..16]);
    right.copy_from_slice(&key_to_derive[16..]);

    let key = Arc::from(enc_key);

    let handle = {
        let key = Arc::clone(&key);
        thread::spawn(move || transform_inner(left, rounds, &key))
    };

    let r = transform_inner(right, rounds, &key);
    let l = handle
        .join()
        .expect("Could not transform key (AES-KDF: failed to join a thread).");

    derived[..16].copy_from_slice(&l);
    derived[16..].copy_from_slice(&r);

    sha256(&derived)
}

fn transform_inner(input: [u8; 16], rounds: u64, key: &[u8]) -> [u8; 16] {
    let mut block = GenericArray::from(input);
    let enc = Aes256::new(key.into());
    for _ in 0..rounds {
        enc.encrypt_block(&mut block);
    }
    let mut output = [0; 16];
    output.copy_from_slice(block.as_slice());
    output
}

fn sha256(slice: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.input(&slice);
    h.result().as_slice().to_vec()
}
