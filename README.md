# KDBX4 [![crates.io](https://img.shields.io/crates/v/kdbx4.svg)](https://crates.io/crates/kdbx4) [![docs.rs](https://docs.rs/kdbx4/badge.svg)](https://docs.rs/kdbx4)

This is an implementation of KeePass database file reader in Rust. This crate aims to work with [KDBX version 4] format.

[KDBX version 4]: https://keepass.info/help/kb/kdbx_4.html

## Usage example

```rust
use kdbx4::{Kdbx4,CompositeKey};

let key = CompositeKey::new(Some("P@ssW0rd"), Some("~/.secret")).unwrap();
let db = Kdbx4::open("~/passwords.kdbx", key).unwrap();

match db.find("example.com").as_slice() {
    [entry] => println!("{}", entry),
    _ => panic!("Expecting single entry with provided title"),
}
```

## Similar projects

At the time of writing, these were not supporting version 4 databases.

- [rust-kpdb](https://github.com/sru-systems/rust-kpdb)
- [rust-keepass](https://github.com/raymontag/rust-keepass)
- [keepass-rs](https://github.com/sseemayer/keepass-rs)

## License

MIT/Unlicensed
