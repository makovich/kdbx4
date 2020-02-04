use super::*;

use crate::error::Error;
use crate::Result as KdbxResult;

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;

/// Struct representing a password entry.
///
/// Collection of attributes like title and the password itself.
#[derive(Debug)]
pub struct Entry<'a> {
    pub(super) uuid: &'a str,
    pub(super) title: &'a str,
    pub(super) password: (&'a str, usize),
    pub(super) history: Option<Vec<Entry<'a>>>,
    pub(super) database: Cell<Option<&'a Database>>,
    pub(super) group: Vec<&'a str>,
    pub(super) props: HashMap<&'a str, &'a str>,
}

impl<'a> Entry<'a> {
    pub fn group(&'a self) -> String {
        self.group.join("/")
    }

    pub fn uuid(&'a self) -> &'a str {
        self.uuid
    }

    pub fn title(&'a self) -> &'a str {
        self.title
    }

    pub fn prop(&'a self, key: &str) -> Option<&'a str> {
        self.props.get(key).cloned()
    }

    pub fn password(&'a self) -> KdbxResult<String> {
        let msg = String::from("fatal: backlink from Entry to its Database does not set");

        self.database
            .get()
            .ok_or_else(|| Error::Other(msg))?
            .cipher
            .decrypt_offset(self.password.0, self.password.1)
    }
}

impl<'a> fmt::Display for Entry<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut props = self.props.clone();

        props.remove("UUID");
        props.remove("Title");
        props.remove("Password");

        writeln!(f, "  Title: {}", self.title)?;
        writeln!(f, "  Group: //{}", self.group.join("/"))?;

        {
            let mut maybe_write = |prop: &str| {
                props
                    .remove(prop)
                    .filter(|v| !v.is_empty())
                    .map(|v| writeln!(f, "  {}: {}", prop, v));
            };

            maybe_write("UserName");
            maybe_write("URL");
            maybe_write("Notes");
        }

        // Display the rest
        for (k, v) in props {
            writeln!(f, "  {}: {}", k, v)?
        }

        Ok(())
    }
}
