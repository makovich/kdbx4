use kdbx4::*;

macro_rules! open_and_read {
    ($testname:ident, $password:expr, $keyfile:expr) => {
        #[test]
        fn $testname() {
            let entry_title = "Bar";
            let entry_pass = "BarPassword3";

            let bytes = include_bytes!(concat!(stringify!($testname), ".kdbx"));

            let key = CompositeKey::new($password, $keyfile).unwrap();
            let db = Kdbx4::open_bytes(&bytes[..], key).unwrap();

            match &db.find(entry_title)[..] {
                [single] => assert_eq!(single.password().unwrap(), entry_pass),
                _ => panic!("Database contains more than one entry with `Foo` title."),
            }
        }
    };
}

open_and_read!(aes_aes_gzip_pwd, Some("P@ssw0rd"), None::<String>);
open_and_read!(aes_argon_gzip_pwd, Some("P@ssw0rd"), None::<String>);
open_and_read!(chacha_argon_gzip_pwd, Some("P@ssw0rd"), None::<String>);
open_and_read!(chacha_argon_keyfile, None, Some("tests/secret"));
open_and_read!(
    chacha_argon_keyfile_pwd_gzip,
    Some("P@ssw0rd"),
    Some("tests/secret")
);