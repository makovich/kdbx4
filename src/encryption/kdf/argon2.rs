use argon2::{self, Config, Variant::*};

#[derive(Debug)]
pub struct Params {
    pub(super) iterations: u32,
    pub(super) parallelism: u32,
    pub(super) memory: u32,
    pub(super) salt: Vec<u8>,
    pub(super) secret_key: Vec<u8>,
    pub(super) assoc_data: Vec<u8>,
}

pub(super) fn transform_d(key: &[u8], params: &Params) -> Vec<u8> {
    transform(key, Argon2d, params)
}

pub(super) fn transform_id(key: &[u8], params: &Params) -> Vec<u8> {
    transform(key, Argon2id, params)
}

fn transform(key: &[u8], variant: argon2::Variant, params: &Params) -> Vec<u8> {
    let config = Config {
        variant,
        version: argon2::Version::Version13,
        hash_length: 32,
        mem_cost: params.memory / 1024,
        time_cost: params.iterations,
        thread_mode: argon2::ThreadMode::Parallel,
        lanes: params.parallelism,
        secret: params.secret_key.as_ref(),
        ad: params.assoc_data.as_ref(),
    };

    argon2::hash_raw(key, params.salt.as_ref(), &config).unwrap()
}
