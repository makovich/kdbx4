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

    pub(super) fn parse(&self) -> KdbxResult<Vec<Entry>> {
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
                Some(Ok(start @ ElementStart { prefix, local, .. })) => {
                    // Recreating our match
                    self.buf.push_front(Ok(start));

                    // Looping because of zero-to-many attributes
                    for nxt in self.tzr.by_ref() {
                        match nxt {
                            // Leaving `name="value"` as it is and moving forward
                            Ok(Attribute { .. }) => self.buf.push_back(nxt),

                            // Replacing `/>` with `>` and `</ns:tag>` and done
                            Ok(ElementEnd { end: Empty, span }) => {
                                self.buf.push_back(Ok(ElementEnd { end: Open, span }));
                                self.buf.push_back(Ok(ElementEnd {
                                    end: Close(prefix, local),
                                    span,
                                }));
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
        if let Value::Plain(val) = self {
            val
        } else {
            "(protected)"
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
                ElementStart { ref local, .. } if a("Group", local) => {
                    group.push(self.read_group_name()?);
                }

                ElementEnd {
                    end: Close(_, ref local),
                    ..
                } if a("Group", local) => {
                    group.pop();
                }

                ElementStart { ref local, .. } if a("Entry", local) => {
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
                ElementStart { ref local, .. } if a("Name", local) => {
                    let (_, v) = self.read_text(local.as_str())?;
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
                ElementStart { ref local, .. } if a("UUID", local) => {
                    let (k, v) = self.read_text(local.as_str())?;
                    map.insert(k, v);
                }

                ElementEnd {
                    end: Close(_, ref local),
                    ..
                } if a("Entry", local) => {
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

                ElementStart { ref local, .. } if a("History", local) && !is_hist => {
                    hist = self.read_history()?;
                }

                ElementStart { ref local, .. } if a("String", local) => {
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
                ElementStart { ref local, .. } if a("Entry", local) => {
                    let entry = self.read_entry(true)?;
                    result.push(entry);
                }

                ElementStart { ref local, .. } if a("History", local) => {
                    error!("fatal: malformed XML (<History> tag inside Entry's history)");
                    return Err(Error::XmlParse);
                }

                ElementEnd {
                    end: Close(_, ref local),
                    ..
                } if a("History", local) => {
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

            if let ElementEnd {
                end: Close(_, ref local),
                ..
            } = token
            {
                if a(tag_name, local) {
                    return Ok((tag_name, Value::Plain(val)));
                }

                error!("fatal: malformed XML (`{}` tag)", tag_name);
                return Err(Error::XmlParse);
            }

            if let Text { text } = token {
                val = text.as_str();
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
                ElementStart { ref local, .. } if a("Key", local) => {
                    key = loop {
                        if let Some(Ok(Text { text })) = self.tzr.next() {
                            break text.as_str();
                        }
                    };
                }

                // `<Value/>` shold not be there
                ElementStart { ref local, .. } if a("Value", local) => {
                    val = loop {
                        let token = self.tzr.next().ok_or(Error::XmlParse)??;

                        // `</Value>` have been met
                        if let ElementEnd { end: Close(..), .. } = token {
                            break "";
                        }

                        // Text inside of the `<Value>` tag
                        if let Text { text } = token {
                            break text.as_str();
                        }

                        if let Attribute {
                            ref local,
                            ref value,
                            ..
                        } = token
                        {
                            protected = a("Protected", local) && a("True", value);
                            // <String>
                            //   <Key>Password</Key>
                            //   <Value Protected="True">XXXXXX</Value>
                            // </String>
                        }
                    };
                }

                // Got closing `</String>` tag
                // Time to return the KV pair
                ElementEnd {
                    end: Close(_, ref local),
                    ..
                } if a("String", local) => {
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
    tag.as_str().eq(name)
}
