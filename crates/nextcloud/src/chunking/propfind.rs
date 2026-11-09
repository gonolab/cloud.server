//! `PROPFIND` on the upload namespace, so that clients can resume an upload: they list the
//! session directory and upload only the chunks that are missing or have the wrong size.
//!
//! Upload sessions are not part of the file tree served by dav-server, so their multistatus is
//! rendered here. The properties are the ones clients read from a chunk listing; any other
//! requested property is reported in a `404 Not Found` propstat.

use std::time::SystemTime;

/// One entry of the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Item {
    /// Percent-encoded href; collections end with `/`.
    pub href: String,
    /// The uploads root or a session (a collection), or a chunk (a file).
    pub collection: bool,
    /// Chunk length (0 for collections).
    pub size: u64,
    /// Last modification.
    pub modified: SystemTime,
    /// ETag without quotes.
    pub etag: String,
}

/// What the PROPFIND body asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Requested {
    /// `<D:prop>`: these `(namespace, name)` pairs.
    Props(Vec<(String, String)>),
    /// `<D:allprop>` or an empty body.
    AllProps,
    /// `<D:propname>`.
    Names,
}

const DAV: &str = "DAV:";

/// The properties an upload listing knows, in output order.
const KNOWN: &[&str] = &[
    "resourcetype",
    "getcontentlength",
    "getlastmodified",
    "getetag",
];

/// Parses a PROPFIND body. `None` if it is not a `DAV:propfind` document.
pub(super) fn requested(body: &[u8]) -> Option<Requested> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Some(Requested::AllProps);
    }
    let root = xmltree::Element::parse(body).ok()?;
    if root.name != "propfind" || root.namespace.as_deref() != Some(DAV) {
        return None;
    }
    let children = || {
        root.children
            .iter()
            .filter_map(xmltree::XMLNode::as_element)
            .filter(|element| element.namespace.as_deref() == Some(DAV))
    };
    if let Some(prop) = children().find(|element| element.name == "prop") {
        let props = prop
            .children
            .iter()
            .filter_map(xmltree::XMLNode::as_element)
            .map(|element| {
                (
                    element.namespace.clone().unwrap_or_default(),
                    element.name.clone(),
                )
            })
            .collect();
        return Some(Requested::Props(props));
    }
    if children().any(|element| element.name == "propname") {
        return Some(Requested::Names);
    }
    Some(Requested::AllProps)
}

/// The value of a known property of `item`, or `None` if the item does not have it.
fn value(item: &Item, name: &str) -> Option<String> {
    match name {
        "resourcetype" => Some(if item.collection {
            "<d:collection/>".to_owned()
        } else {
            String::new()
        }),
        "getcontentlength" => (!item.collection).then(|| item.size.to_string()),
        "getlastmodified" => Some(httpdate::fmt_http_date(item.modified)),
        "getetag" => Some(format!("&quot;{}&quot;", item.etag)),
        _ => None,
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Renders the multistatus for `items`.
pub(super) fn render(items: &[Item], requested: &Requested) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:multistatus xmlns:d=\"DAV:\">",
    );
    for item in items {
        xml.push_str("<d:response><d:href>");
        xml.push_str(&escape(&item.href));
        xml.push_str("</d:href>");
        let mut found = String::new();
        let mut missing = String::new();
        let mut unknown = 0;
        let mut element = |out: &mut String, namespace: &str, name: &str, value: Option<&str>| {
            let (open, close) = if namespace == DAV {
                (format!("d:{name}"), format!("d:{name}"))
            } else if namespace.is_empty() {
                (format!("{name} xmlns=\"\""), name.to_owned())
            } else {
                unknown += 1;
                (
                    format!(
                        "x{unknown}:{name} xmlns:x{unknown}=\"{}\"",
                        escape(namespace)
                    ),
                    format!("x{unknown}:{name}"),
                )
            };
            match value {
                Some(value) if !value.is_empty() => {
                    out.push_str(&format!("<{open}>{value}</{close}>"));
                }
                _ => out.push_str(&format!("<{open}/>")),
            }
        };
        match requested {
            Requested::Props(props) => {
                for (namespace, name) in props {
                    let known = (namespace == DAV).then(|| value(item, name)).flatten();
                    match known {
                        Some(value) => element(&mut found, namespace, name, Some(&value)),
                        None => element(&mut missing, namespace, name, None),
                    }
                }
            }
            Requested::AllProps => {
                for name in KNOWN {
                    if let Some(value) = value(item, name) {
                        element(&mut found, DAV, name, Some(&value));
                    }
                }
            }
            Requested::Names => {
                for name in KNOWN {
                    if value(item, name).is_some() {
                        element(&mut found, DAV, name, None);
                    }
                }
            }
        }
        for (props, status) in [(found, "200 OK"), (missing, "404 Not Found")] {
            if !props.is_empty() {
                xml.push_str(&format!(
                    "<d:propstat><d:prop>{props}</d:prop><d:status>HTTP/1.1 {status}</d:status></d:propstat>"
                ));
            }
        }
        xml.push_str("</d:response>");
    }
    xml.push_str("</d:multistatus>\n");
    xml
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    fn items() -> Vec<Item> {
        vec![
            Item {
                href: "/remote.php/dav/uploads/alice/up%201/".into(),
                collection: true,
                size: 0,
                modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
                etag: "s1".into(),
            },
            Item {
                href: "/remote.php/dav/uploads/alice/up%201/00001".into(),
                collection: false,
                size: 5,
                modified: UNIX_EPOCH,
                etag: "c1".into(),
            },
        ]
    }

    #[test]
    fn requested_properties_and_404s() {
        let body = br#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><d:getcontentlength/><d:resourcetype/><oc:fileid/></d:prop></d:propfind>"#;
        let requested = requested(body).unwrap();
        let xml = render(&items(), &requested);
        assert!(xmltree::Element::parse(xml.as_bytes()).is_ok(), "{xml}");
        assert!(xml.contains("<d:href>/remote.php/dav/uploads/alice/up%201/</d:href>"));
        assert!(
            xml.contains("<d:getcontentlength>5</d:getcontentlength>"),
            "{xml}"
        );
        assert!(
            xml.contains("<d:resourcetype><d:collection/></d:resourcetype>"),
            "{xml}"
        );
        assert!(
            xml.contains("<x1:fileid xmlns:x1=\"http://owncloud.org/ns\"/>"),
            "{xml}"
        );
        assert!(xml.contains("404 Not Found"), "{xml}");
        // Collections have no length.
        let collection = xml.split("</d:response>").next().unwrap();
        assert!(!collection.contains("<d:getcontentlength>"), "{collection}");
    }

    #[test]
    fn allprop_and_propname() {
        assert_eq!(requested(b""), Some(Requested::AllProps));
        assert_eq!(requested(b"<x/>"), None);
        let all = render(&items(), &Requested::AllProps);
        assert!(
            all.contains("<d:getetag>&quot;c1&quot;</d:getetag>"),
            "{all}"
        );
        assert!(all.contains("Tue, 14 Nov 2023 22:13:20 GMT"), "{all}");
        let names = requested(br#"<d:propfind xmlns:d="DAV:"><d:propname/></d:propfind>"#).unwrap();
        assert_eq!(names, Requested::Names);
        assert!(render(&items(), &names).contains("<d:getetag/>"));
    }
}
