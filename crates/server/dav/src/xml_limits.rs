//! Limits for XML request bodies.
//!
//! dav-server and the handlers in this workspace parse XML request bodies with xmltree, which
//! builds the element tree recursively, one stack frame per nesting level. A body of a few
//! kilobytes with a few thousand nested elements therefore overflows the 2 MiB stack of a
//! tokio worker thread, and a stack overflow aborts the whole process, not just the request.
//!
//! The router reads the body of every method in [`parses_body`] (at most [`MAX_BODY`] bytes,
//! the limit all of these parsers already apply) and refuses it with 400 when
//! [`exceeds_depth`] reports more than [`MAX_DEPTH`] nested elements. [`exceeds_depth`] uses a
//! streaming parser that keeps no stack of its own, so it is safe for any input. The parsers
//! that rely on this check:
//!
//! - dav-server: `PROPFIND`, `PROPPATCH` and `LOCK` bodies, and the dead properties and lock
//!   owners it stores from them and parses again later. Since 0.12.0 dav-server also refuses
//!   bodies and stored property XML nested deeper than 64 levels itself (GHSA-jj29-x8v4-w733);
//! - [`crate::ctx::PropfindKind::of_body`] (`PROPFIND`);
//! - [`crate::report`] (`REPORT`);
//! - the `PROPFIND` of the chunked upload namespace (`gono-server-nextcloud`).

use http::Method;
use xml::reader::{EventReader, XmlEvent};

/// Largest XML request body accepted, in bytes. dav-server's own limit for the bodies it
/// parses; the `REPORT` and chunked upload `PROPFIND` handlers use the same value.
pub const MAX_BODY: usize = 64 * 1024;

/// Deepest element nesting accepted in an XML request body.
///
/// WebDAV and Nextcloud bodies nest a handful of levels (`propfind/prop/getetag`,
/// `propertyupdate/set/prop/<property>/<value>`, `lockinfo/owner/href`); dead property values
/// may carry XML of their own, for which this leaves ample room. The limit is far below the
/// depth at which xmltree overflows a 2 MiB stack (about 3000 levels in release builds, about
/// 1000 in debug builds).
pub const MAX_DEPTH: usize = 64;

/// Whether requests with `method` carry a body that is parsed as XML.
pub fn parses_body(method: &Method) -> bool {
    matches!(
        method.as_str(),
        "PROPFIND" | "PROPPATCH" | "LOCK" | "REPORT"
    )
}

/// Whether the elements of `body` nest deeper than `max_depth`.
///
/// Bodies that are not well-formed XML are not judged here: the scan stops at the first
/// error, which the regular parser then reports. Every parser in the workspace is built on the
/// same `xml` crate, so none of them gets past that error either, and a deep body is reported
/// before its first error is reached.
pub fn exceeds_depth(body: &[u8], max_depth: usize) -> bool {
    let mut depth = 0usize;
    for event in EventReader::new(body) {
        match event {
            Ok(XmlEvent::StartElement { .. }) => {
                depth += 1;
                if depth > max_depth {
                    return true;
                }
            }
            Ok(XmlEvent::EndElement { .. }) => depth = depth.saturating_sub(1),
            Ok(XmlEvent::EndDocument) | Err(_) => return false,
            Ok(_) => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `depth` nested elements inside a DAV `propfind` root (which counts as one level).
    fn nested(depth: usize, closed: bool) -> String {
        let mut xml = String::from(r#"<?xml version="1.0"?><D:propfind xmlns:D="DAV:">"#);
        xml.push_str(&"<a>".repeat(depth - 1));
        if closed {
            xml.push_str(&"</a>".repeat(depth - 1));
            xml.push_str("</D:propfind>");
        }
        xml
    }

    #[test]
    fn the_limit_itself_is_accepted() {
        assert!(!exceeds_depth(
            nested(MAX_DEPTH, true).as_bytes(),
            MAX_DEPTH
        ));
        assert!(exceeds_depth(
            nested(MAX_DEPTH + 1, true).as_bytes(),
            MAX_DEPTH
        ));
    }

    #[test]
    fn unclosed_deep_bodies_are_reported_before_the_parse_error() {
        assert!(exceeds_depth(nested(3000, false).as_bytes(), MAX_DEPTH));
        assert!(exceeds_depth(nested(30_000, false).as_bytes(), MAX_DEPTH));
    }

    #[test]
    fn siblings_do_not_add_up() {
        let mut xml = String::from(r#"<D:propfind xmlns:D="DAV:"><D:prop>"#);
        for _ in 0..5000 {
            xml.push_str("<D:getetag/><x:a xmlns:x=\"urn:x\"><x:b>text</x:b></x:a>");
        }
        xml.push_str("</D:prop></D:propfind>");
        // propfind > prop > x:a > x:b: four levels, however many siblings there are.
        assert!(!exceeds_depth(xml.as_bytes(), 4));
        assert!(exceeds_depth(xml.as_bytes(), 3));
    }

    #[test]
    fn markup_that_is_not_an_element_does_not_count() {
        let xml = r#"<?xml version="1.0"?>
            <!-- <a><a><a> -->
            <D:propfind xmlns:D="DAV:"><![CDATA[<a><a><a>]]><?pi <a><a>?>&lt;a&gt;</D:propfind>"#;
        assert!(!exceeds_depth(xml.as_bytes(), 1));
    }

    #[test]
    fn bodies_that_are_not_xml_are_left_to_the_parser() {
        for body in ["", "   ", "not xml", "<a><b></a>", "<a/><b/>"] {
            assert!(!exceeds_depth(body.as_bytes(), 2), "{body:?}");
        }
        // The depth reached before the error still counts.
        assert!(exceeds_depth(b"<a><b></a>", 1));
    }

    #[test]
    fn only_methods_with_xml_bodies_are_checked() {
        for method in ["PROPFIND", "PROPPATCH", "LOCK", "REPORT"] {
            assert!(parses_body(&Method::from_bytes(method.as_bytes()).unwrap()));
        }
        for method in [
            Method::GET,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
            Method::from_bytes(b"MKCOL").unwrap(),
            Method::from_bytes(b"MOVE").unwrap(),
            Method::from_bytes(b"UNLOCK").unwrap(),
        ] {
            assert!(!parses_body(&method), "{method}");
        }
    }
}
