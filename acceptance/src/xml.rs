//! Minimal namespace-aware XML tree and WebDAV multistatus parsing.

use quick_xml::{
    NsReader,
    events::Event,
    name::{Namespace, ResolveResult},
};

pub const DAV: &str = "DAV:";
pub const OC: &str = "http://owncloud.org/ns";
pub const NC: &str = "http://nextcloud.org/ns";

/// An XML element with its resolved namespace, local name, text, and child elements.
#[derive(Debug, Clone, Default)]
pub struct Element {
    pub ns: String,
    pub name: String,
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    pub fn is(&self, ns: &str, name: &str) -> bool {
        self.ns == ns && self.name == name
    }

    pub fn child(&self, ns: &str, name: &str) -> Option<&Element> {
        self.children.iter().find(|child| child.is(ns, name))
    }

    pub fn children_named<'a>(
        &'a self,
        ns: &'a str,
        name: &'a str,
    ) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |child| child.is(ns, name))
    }

    /// Returns all descendants (including `self`) with the given name, in document order.
    pub fn descendants(&self, ns: &str, name: &str) -> Vec<&Element> {
        let mut found = Vec::new();
        self.collect_descendants(ns, name, &mut found);
        found
    }

    fn collect_descendants<'a>(&'a self, ns: &str, name: &str, found: &mut Vec<&'a Element>) {
        if self.is(ns, name) {
            found.push(self);
        }
        for child in &self.children {
            child.collect_descendants(ns, name, found);
        }
    }

    /// The trimmed text content of this element and all of its descendants.
    pub fn all_text(&self) -> String {
        let mut text = self.text.clone();
        for child in &self.children {
            text.push_str(&child.all_text());
        }
        text.trim().to_owned()
    }
}

/// Parses an XML document and returns its root element.
pub fn parse(bytes: &[u8]) -> Result<Element, String> {
    let mut reader = NsReader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut stack: Vec<Element> = vec![Element::default()];

    loop {
        let (resolved, event) = reader
            .read_resolved_event_into(&mut buf)
            .map_err(|err| format!("invalid XML: {err}"))?;
        let ns = namespace_string(&resolved);
        match event {
            Event::Start(start) => stack.push(Element {
                ns,
                name: String::from_utf8_lossy(start.local_name().as_ref()).into_owned(),
                ..Element::default()
            }),
            Event::Empty(empty) => {
                let element = Element {
                    ns,
                    name: String::from_utf8_lossy(empty.local_name().as_ref()).into_owned(),
                    ..Element::default()
                };
                stack
                    .last_mut()
                    .expect("XML stack always has a document node")
                    .children
                    .push(element);
            }
            Event::End(_) => {
                let element = stack.pop().expect("XML stack always has a document node");
                let parent = stack
                    .last_mut()
                    .ok_or_else(|| "unbalanced XML end tag".to_owned())?;
                parent.children.push(element);
            }
            Event::Text(text) => {
                let text = text
                    .unescape()
                    .map_err(|err| format!("invalid XML text: {err}"))?;
                stack
                    .last_mut()
                    .expect("XML stack always has a document node")
                    .text
                    .push_str(&text);
            }
            Event::CData(data) => stack
                .last_mut()
                .expect("XML stack always has a document node")
                .text
                .push_str(&String::from_utf8_lossy(&data.into_inner())),
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    if stack.len() != 1 {
        return Err("unterminated XML element".to_owned());
    }
    let document = stack.pop().expect("document node");
    document
        .children
        .into_iter()
        .next()
        .ok_or_else(|| "XML document has no root element".to_owned())
}

fn namespace_string(resolved: &ResolveResult<'_>) -> String {
    match resolved {
        ResolveResult::Bound(Namespace(ns)) => String::from_utf8_lossy(ns).into_owned(),
        _ => String::new(),
    }
}

/// A parsed `DAV:multistatus` body.
#[derive(Debug, Clone)]
pub struct Multistatus {
    pub responses: Vec<DavResponse>,
}

/// One `DAV:response` element. `path` is the percent-decoded path of its href without a trailing
/// slash, e.g. `/remote.php/dav/files/alice/dir`.
#[derive(Debug, Clone)]
pub struct DavResponse {
    pub href: String,
    pub path: String,
    pub status: Option<u16>,
    pub propstats: Vec<PropStat>,
}

#[derive(Debug, Clone)]
pub struct PropStat {
    pub status: u16,
    pub props: Vec<Element>,
}

impl Multistatus {
    pub fn parse(bytes: &[u8]) -> Result<Multistatus, String> {
        let root = parse(bytes)?;
        if !root.is(DAV, "multistatus") {
            return Err(format!(
                "expected DAV:multistatus root, got {{{}}}{}",
                root.ns, root.name
            ));
        }
        let mut responses = Vec::new();
        for response in root.children_named(DAV, "response") {
            let href = response
                .child(DAV, "href")
                .map(|href| href.all_text())
                .ok_or_else(|| "DAV:response without DAV:href".to_owned())?;
            let status = response
                .child(DAV, "status")
                .and_then(|status| parse_status_line(&status.all_text()));
            let mut propstats = Vec::new();
            for propstat in response.children_named(DAV, "propstat") {
                let status = propstat
                    .child(DAV, "status")
                    .and_then(|status| parse_status_line(&status.all_text()))
                    .ok_or_else(|| format!("propstat without a valid status in {href}"))?;
                let props = propstat
                    .child(DAV, "prop")
                    .map(|prop| prop.children.clone())
                    .unwrap_or_default();
                propstats.push(PropStat { status, props });
            }
            responses.push(DavResponse {
                path: href_to_path(&href),
                href,
                status,
                propstats,
            });
        }
        Ok(Multistatus { responses })
    }

    /// Finds the response whose decoded href path equals `path` (trailing slashes ignored).
    pub fn get(&self, path: &str) -> Option<&DavResponse> {
        let wanted = path.trim_end_matches('/');
        self.responses
            .iter()
            .find(|response| response.path == wanted)
    }

    pub fn paths(&self) -> Vec<String> {
        self.responses
            .iter()
            .map(|response| response.path.clone())
            .collect()
    }
}

impl DavResponse {
    /// A property reported with a 2xx propstat status.
    pub fn prop(&self, ns: &str, name: &str) -> Option<&Element> {
        self.propstats
            .iter()
            .filter(|propstat| (200..300).contains(&propstat.status))
            .flat_map(|propstat| propstat.props.iter())
            .find(|prop| prop.is(ns, name))
    }

    pub fn text(&self, ns: &str, name: &str) -> Option<String> {
        self.prop(ns, name).map(Element::all_text)
    }

    /// The propstat status reported for a property, if the property appears at all.
    pub fn prop_status(&self, ns: &str, name: &str) -> Option<u16> {
        self.propstats
            .iter()
            .find(|propstat| propstat.props.iter().any(|prop| prop.is(ns, name)))
            .map(|propstat| propstat.status)
    }

    pub fn is_collection(&self) -> bool {
        self.prop(DAV, "resourcetype")
            .is_some_and(|resourcetype| resourcetype.child(DAV, "collection").is_some())
    }
}

fn parse_status_line(line: &str) -> Option<u16> {
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Converts an href (absolute path or absolute URL) to its decoded path without trailing slash.
pub fn href_to_path(href: &str) -> String {
    let path = match url::Url::parse(href) {
        Ok(url) if url.has_host() => url.path().to_owned(),
        _ => href.to_owned(),
    };
    let decoded = percent_encoding::percent_decode_str(&path)
        .decode_utf8_lossy()
        .into_owned();
    let trimmed = decoded.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Escapes text for inclusion in an XML element or attribute.
pub fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
