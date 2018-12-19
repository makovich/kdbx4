use crypto::aes::KeySize;
use crypto::aesni::AesNiEncryptor;
use crypto::aessafe::AesSafe256Encryptor;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::BlockEncryptor;
use crypto::util::supports_aesni;

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

fn transform_inner(mut input: [u8; 16], rounds: u64, key: &[u8]) -> [u8; 16] {
    let enc = create_encryptor(&key);
    let mut output = [0; 16];
    for _ in 0..rounds {
        enc.encrypt_block(&input, &mut output);
        input.copy_from_slice(&output);
    }
    output
}

fn create_encryptor(key: &[u8]) -> Box<BlockEncryptor> {
    if supports_aesni() {
        Box::new(AesNiEncryptor::new(KeySize::KeySize256, key))
    } else {
        Box::new(AesSafe256Encryptor::new(key))
    }
}

fn sha256(slice: &[u8]) -> Vec<u8> {
    let mut hash = [0; 32];
    let mut h = Sha256::new();
    h.input(&slice);
    h.result(&mut hash);
    hash.to_vec()
}
