use crate::error::Error;
use crate::Entry;
use crate::Result as KdbxResult;

use log::*;

use xmlparser::ElementEnd::*;
use xmlparser::Error as XmlError;
use xmlparser::StrSpan;
use xmlparser::Token;
use xmlparser::Token::*;
use xmlparser::Tokenizer;

use base64;

use pretty_hex::PrettyHex;

use std::cell::Cell;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt::{self, Debug};

#[doc(hidden)]
#[derive(Clone)]
pub struct Xml(String);

impl Xml {
    pub(crate) fn try_from(v: Vec<u8>) -> KdbxResult<Xml> {
        debug!(
            "converting bytes to string (shown first 32 bytes)\n{:?}",
            v[..32].as_ref().hex_dump()
        );

        String::from_utf8(v).map(Xml).map_err(From::from)
    }

    pub(super) fn parse<'a>(&'a self) -> KdbxResult<Vec<Entry<'a>>> {
        XmlParser::parse(&self.0)
    }
}

impl Debug for Xml {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "XML {} bytes", self.0.len())
    }
}

struct FakeCloseTagAdaptor<'a> {
    tzr: Tokenizer<'a>,
    buf: VecDeque<Result<Token<'a>, XmlError>>,
}

impl<'a> Iterator for FakeCloseTagAdaptor<'a> {
    type Item = Result<Token<'a>, XmlError>;

    fn next(&mut self) -> Option<Self::Item> {
        // The next tokens buffer is empty
        // Let's take one from XML source
        if self.buf.is_empty() {
            match self.tzr.next() {
                // Nothing in there. End of sequence.
                None => return None,

                // This is what we need: `<ns:tag`
                Some(Ok(ElementStart(ns, tag))) => {
                    // Recreating our match
                    self.buf.push_front(Ok(ElementStart(ns, tag)));

                    // Looping because of zero-to-many attributes
                    while let Some(nxt) = self.tzr.next() {
                        match nxt {
                            // Leaving `name="value"` as it is and moving forward
                            Ok(Attribute(_, _)) => self.buf.push_back(nxt),

                            // Replacing `/>` with `>` and `</ns:tag>` and done
                            Ok(ElementEnd(Empty)) => {
                                self.buf.push_back(Ok(ElementEnd(Open)));
                                self.buf.push_back(Ok(ElementEnd(Close(ns, tag))));
                                break;
                            }

                            // Anything else should be only `>`
                            // Leaving as is and going from loop out
                            _ => {
                                self.buf.push_back(nxt);
                                break;
                            }
                        }
                    }
                }

                // All non starting elements are just fine
                Some(other) => return Some(other),
            }
        }

        self.buf.pop_front()
    }
}

enum Value<'a> {
    Plain(&'a str),
    Protected(&'a str, usize),
}

impl<'a> Value<'a> {
    fn plain(&self) -> &'a str {
        if let Value::Plain(ref val) = self {
            val
        } else {
            &"(protected)"
        }
    }

    fn protected(&self) -> (&'a str, usize) {
        if let Value::Protected(val, ofs) = self {
            (val, *ofs)
        } else {
            panic!("fatal: attempt to get a plain value from protected one")
        }
    }
}

struct XmlParser<'a> {
    tzr: FakeCloseTagAdaptor<'a>,
    pb: usize,
}

/// Parses XML with expected schema:
///
///    <Group>
///        <Name>Root</Name>
///        <Entry>
///            ...
///            <String>
///                <Key>Notes</Key>
///                <Value/>
///            </String>
///            <String>
///                <Key>Title</Key>
///                <Value>reddit.com</Value>
///            </String>
///            <String>
///                <Key>Password</Key>
///                <Value Protected="True">XXXXXX</Value>
///            </String>
///            <History>
///                <Entry>
///                    ...
///                </Entry>
///            </History>
///        </Entry>
///    </Group>
///
impl<'a> XmlParser<'a> {
    pub fn parse(xml: &'a str) -> KdbxResult<Vec<Entry<'a>>> {
        XmlParser {
            tzr: FakeCloseTagAdaptor {
                tzr: Tokenizer::from(xml),
                buf: VecDeque::new(),
            },
            pb: 0,
        }
        .parse_internal()
    }

    fn parse_internal(&mut self) -> KdbxResult<Vec<Entry<'a>>> {
        let mut result = Vec::new();
        let mut group = Vec::new();

        while let Some(token) = self.tzr.next() {
            match token? {
                ElementStart(_, ref tag) if a("Group", tag) => {
                    group.push(self.read_group_name()?);
                }

                ElementEnd(Close(_, ref tag)) if a("Group", tag) => {
                    group.pop();
                }

                ElementStart(_, ref tag) if a("Entry", tag) => {
                    let mut entry = self.read_entry(false)?;

                    // Update entry's group
                    entry.group = group.clone();

                    result.push(entry);
                }

                _ => {}
            }
        }

        Ok(result)
    }

    fn read_group_name(&mut self) -> KdbxResult<&'a str> {
        loop {
            let token = self.tzr.next().ok_or(Error::XmlParse)??;

            match token {
                ElementStart(_, ref tag) if a("Name", tag) => {
                    let (_, v) = self.read_text(tag.to_str())?;
                    return Ok(v.plain());
                }

                _ => {}
            }
        }
    }

    fn read_entry(&mut self, is_hist: bool) -> KdbxResult<Entry<'a>> {
        let mut map = HashMap::new();
        let mut hist: Option<Vec<Entry<'a>>> = None;

        loop {
            let token = self.tzr.next().ok_or(Error::XmlParse)??;

            match token {
                ElementStart(_, ref tag) if a("UUID", tag) => {
                    let (k, v) = self.read_text(tag.to_str())?;
                    map.insert(k, v);
                }

                ElementEnd(Close(_, ref tag)) if a("Entry", tag) => {
                    return Ok(Entry {
                        props: map.iter().fold(HashMap::new(), |mut acc, (k, v)| {
                            acc.insert(k, v.plain());
                            acc
                        }),
                        uuid: map["UUID"].plain(),
                        title: map["Title"].plain(),
                        password: map["Password"].protected(),
                        history: if is_hist { None } else { hist },
                        database: Cell::new(None),
                        group: Vec::new(),
                    });
                }

                ElementStart(_, ref tag) if a("History", tag) && !is_hist => {
                    hist = self.read_history()?;
                }

                ElementStart(_, ref tag) if a("String", tag) => {
                    let (k, v) = self.read_kvpair()?;
                    map.insert(k, v);
                }
                _ => {}
            }
        }
    }

    fn read_history(&mut self) -> KdbxResult<Option<Vec<Entry<'a>>>> {
        let mut result = Vec::new();

        loop {
            let token = self.tzr.next().ok_or(Error::XmlParse)??;

            match token {
                ElementStart(_, ref tag) if a("Entry", tag) => {
                    let entry = self.read_entry(true)?;
                    result.push(entry);
                }

                ElementStart(_, ref tag) if a("History", tag) => {
                    error!("fatal: malformed XML (<History> tag inside Entry's history)");
                    return Err(Error::XmlParse);
                }

                ElementEnd(Close(_, ref tag)) if a("History", tag) => {
                    return if result.is_empty() {
                        Ok(None)
                    } else {
                        Ok(Some(result))
                    }
                }

                _ => {}
            }
        }
    }

    fn read_text(&mut self, tag_name: &'a str) -> KdbxResult<(&'a str, Value<'a>)> {
        let mut val = "";

        loop {
            let token = self.tzr.next().ok_or(Error::XmlParse)??;

            if let ElementEnd(Close(_, ref tag)) = token {
                if a(tag_name, tag) {
                    return Ok((tag_name, Value::Plain(val)));
                }

                error!("fatal: malformed XML (`{}` tag)", tag_name);
                return Err(Error::XmlParse);
            }

            if let Text(txt) = token {
                val = txt.to_str();
            }
        }
    }

    fn read_kvpair(&mut self) -> KdbxResult<(&'a str, Value<'a>)> {
        let mut key = "";
        let mut val = "";
        let mut protected = false;

        loop {
            let token = self.tzr.next().ok_or(Error::XmlParse)??;

            match token {
                // Assuming `<Key>` tag always have its closing pair `</Key>`
                ElementStart(_, ref tag) if a("Key", tag) => {
                    key = loop {
                        if let Some(Ok(Text(txt))) = self.tzr.next() {
                            break txt.to_str();
                        }
                    };
                }

                // `<Value/>` shold not be there
                ElementStart(_, ref tag) if a("Value", tag) => {
                    val = loop {
                        let token = self.tzr.next().ok_or(Error::XmlParse)??;

                        // `</Value>` have been met
                        if let ElementEnd(Close(_, _)) = token {
                            break "";
                        }

                        // Text inside of the `<Value>` tag
                        if let Text(txt) = token {
                            break txt.to_str();
                        }

                        if let Attribute((_, ref n), ref v) = token {
                            protected = a("Protected", n) && a("True", v);
                            // <String>
                            //   <Key>Password</Key>
                            //   <Value Protected="True">XXXXXX</Value>
                            // </String>
                        }
                    };
                }

                // Got closing `</String>` tag
                // Time to return the KV pair
                ElementEnd(Close(_, ref tag)) if a("String", tag) => {
                    if protected {
                        // Length of the protected binary in bytes
                        let len = base64::decode(val).map(|v| v.len()).unwrap_or(0);

                        // Protected binary stream global offset
                        let ofs = self.pb;

                        // Adjusting the global offset
                        self.pb += len;

                        return Ok((key, Value::Protected(val, ofs)));
                    } else {
                        return Ok((key, Value::Plain(val)));
                    }
                }

                _ => {}
            }
        }
    }
}

fn a(name: &str, tag: &StrSpan) -> bool {
    tag.to_str().eq(name)
}
