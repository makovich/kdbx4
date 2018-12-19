use argon2::{self, Config};

pub(super) fn transform(
    key: &[u8],
    iterations: u32,
    parallelism: u32,
    memory: u32,
    salt: &[u8],
    secret_key: &[u8],
    assoc_data: &[u8],
) -> Vec<u8> {
    let config = Config {
        variant: argon2::Variant::Argon2d,
        version: argon2::Version::Version13,
        hash_length: 32,
        mem_cost: memory / 1024,
        time_cost: iterations,
        thread_mode: argon2::ThreadMode::Parallel,
        lanes: parallelism,
        secret: secret_key,
        ad: assoc_data,
    };

    argon2::hash_raw(key, salt, &config).unwrap()
}
