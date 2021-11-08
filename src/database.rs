mod binaries;
mod entry;
mod xml;

pub use self::binaries::Binaries;
pub use self::entry::Entry;
pub use self::xml::Xml;

use crate::encryption::StreamCipher;
use crate::Result as KdbxResult;

use log::*;

/// Provides access to a database XML content.
///
/// # Examples
///
/// ```no_run
/// use kdbx4::{Kdbx4,CompositeKey};
///
/// let key = CompositeKey::new(Some("P@ssW0rd"), None::<String>).unwrap();
/// let db = Kdbx4::open("~/passwords.kdbx", key).unwrap();
///
/// assert!(db.entries().len() >= 0);
/// ```
#[derive(Debug)]
pub struct Database {
    bin: Binaries,
    xml: Xml,
    cipher: StreamCipher,
}

impl Database {
    #[allow(clippy::new_ret_no_self)]
    pub(super) fn new(cipher: StreamCipher, xml: Xml, bin: Binaries) -> KdbxResult<Database> {
        debug!("{:X?}", cipher);
        debug!("{:?}", xml);
        debug!("{:?}", bin);

        // Fail fast if not parsable file format
        xml.parse()?;

        Ok(Database { cipher, xml, bin })
    }

    /// Returns all [`Entry`]s from database.
    ///
    /// [`Entry`]: struct.Entry.html
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use kdbx4::{Kdbx4,CompositeKey};
    /// # let key = CompositeKey::new(Some("P@ssW0rd"), None::<String>).unwrap();
    /// # let db = Kdbx4::open("~/passwords.kdbx", key).unwrap();
    /// let mut total = 0;
    ///
    /// for entry in db.entries() {
    ///   total += 1;
    /// }
    ///
    /// ```
    pub fn entries(&self) -> Vec<Entry> {
        let mut entries = self.xml.parse().expect("Cannot parse XML");

        for entry in &mut entries {
            entry.database.set(Some(self));
        }

        entries
    }

    /// Returns [`Entry`]s with title starting with pattern.
    ///
    /// Matching is case-insensitive.
    ///
    /// [`Entry`]: struct.Entry.html
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use kdbx4::{Kdbx4,CompositeKey};
    /// # let key = CompositeKey::new(Some("P@ssW0rd"), None::<String>).unwrap();
    /// # let db = Kdbx4::open("~/passwords.kdbx", key).unwrap();
    /// assert_eq!(0, db.find("example.com").len());
    /// ```
    pub fn find<'a>(&'a self, title: &'a str) -> Vec<Entry<'a>> {
        let title = title.to_lowercase();

        self.entries()
            .into_iter()
            .filter(|e| e.title.to_lowercase().starts_with(&*title))
            .collect()
    }
}
