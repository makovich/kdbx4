pub const SIG1: u32 = 0x9AA2_D903;
pub const SIG2: u32 = 0xB54B_FB67;
pub const VERSION: u32 = 0x0004_0000;
pub const VD_VER: u16 = 0x0100;
pub const HEADER_BLK_IDX: u64 = ::std::u64::MAX;
pub const SALSA20_IV: &[u8] = &[0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
pub const EMPTY: &[u8] = &[];

pub mod uuid {
    pub const ARGON2_KDF: &[u8] = &[
        0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A,
        0x0C,
    ];
    pub const AES_KDF: &[u8] = &[
        0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F,
        0xEA,
    ];

    pub const CHACHA20: &[u8] = &[
        0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5,
        0x9A,
    ];
    pub const AES256: &[u8] = &[
        0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A,
        0xFF,
    ];
}

#[allow(dead_code)]
pub mod vd_type {
    pub const NONE: u8 = 0x00;
    pub const UINT32: u8 = 0x04;
    pub const UINT64: u8 = 0x05;
    pub const BOOL: u8 = 0x08;
    pub const INT32: u8 = 0x0C;
    pub const INT64: u8 = 0x0D;
    pub const STRING: u8 = 0x18;
    pub const BYTEARRAY: u8 = 0x42;
}

#[allow(dead_code)]
pub mod vd_param {
    pub const UUID: &str = "$UUID";

    pub mod argon2 {
        pub const SALT: &str = "S";
        pub const PARALLELISM: &str = "P";
        pub const MEMORY: &str = "M";
        pub const ITERATIONS: &str = "I";
        pub const VERSION: &str = "V";
        pub const SECRETKEY: &str = "K";
        pub const ASSOCDATA: &str = "A";

        pub const DEFAULT_ITERATIONS: &[u8] = &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        pub const DEFAULT_PARALLELISM: &[u8] = &[0x02, 0x00, 0x00, 0x00];
        pub const DEFAULT_MEMORY: &[u8] = &[0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00];
    }

    pub mod aes {
        pub const ROUNDS: &str = "R";
        pub const SEED: &str = "S";

        pub const DEFAULT_ROUNDS: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    }
}

#[allow(dead_code)]
pub mod header_type {
    pub const END_OF_HEADER: u8 = 0;
    pub const COMMENT: u8 = 1;
    pub const CIPHER_ID: u8 = 2;
    pub const COMPRESSION_FLAGS: u8 = 3;
    pub const MASTER_SEED: u8 = 4;
    pub const ENCRYPTION_IV: u8 = 7;
    pub const KDF_PARAMETERS: u8 = 11;
    pub const PUBLIC_CUSTOM_DATA: u8 = 12;
}

#[allow(dead_code)]
pub mod inner_header_type {
    pub const END_OF_HEADER: u8 = 0x00;
    pub const STREAM_ID: u8 = 0x01;
    pub const STREAM_KEY: u8 = 0x02;
    pub const BINARY: u8 = 0x03;

    pub const BINARY_PROTECTED: u8 = 0x01;
    pub const BINARY_PLAIN: u8 = 0x00;

    pub const SALSA20_STREAM: u32 = 2;
    pub const CHACHA20_STREAM: u32 = 3;
}
