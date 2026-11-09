//! `REPORT`: the `oc:filter-files` favorites report.
//!
//! dav-server does not know this report, so the server routes every `REPORT` here instead of
//! to [`DavService::handle`]. Only the favorites filter is implemented:
//!
//! ```xml
//! <oc:filter-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
//!   <oc:filter-rules><oc:favorite>1</oc:favorite></oc:filter-rules>
//!   <d:prop><d:getetag/><oc:fileid/></d:prop>
//! </oc:filter-files>
//! ```
//!
//! The answer is a multistatus with one response per favorite anywhere below the request path
//! (all depths, the request path itself excluded), with the requested properties. Every other
//! report, and `filter-files` with other rules (system tags, circles, ...), answers
//! `501 Not Implemented`.
//!
//! # One source for properties
//!
//! The favorites are found in the metadata ([`ScopedFs::favorites_below`]), but their
//! properties are not rendered here: each favorite is looked up with an internal `Depth: 0`
//! PROPFIND for the requested `<D:prop>` through [`DavService::handle`], and the `<D:response>`
//! elements of those answers are joined into one multistatus. The REPORT therefore reports
//! exactly what PROPFIND reports, including the quoted `getetag`, live and dead properties and
//! 404 propstats, and an entry that vanished from the disk is left out. dav-server declares
//! the namespaces of the requested properties on the `multistatus` element, which is the same
//! for every one of these PROPFINDs, so the responses are joined under the first one's root.

use std::sync::Arc;

use bytes::Bytes;
use dav_server::{davpath::DavPath, fs::FsError};
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body::Body;
use http_body_util::{BodyExt as _, Full, Limited};
use xmltree::{Element, XMLNode};

use crate::{
    ctx::{Ctx, RequestInfo},
    identity::Identity,
    props::NS_OC,
    resolve,
    service::{DavBody, DavService, path_is_clean, simple, xml_body},
};

/// Largest accepted REPORT body.
const MAX_REPORT_BODY: usize = 64 * 1024;

/// Why a REPORT body is not served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// Not XML, or not a well-formed `filter-files` request: 400.
    Malformed,
    /// Another report or filter: 501.
    Unsupported,
}

/// A parsed `oc:filter-files` request for favorites.
#[derive(Debug, Clone, PartialEq)]
struct FavoritesQuery {
    /// The `<D:prop>` element, if the request names properties.
    prop: Option<Element>,
}

impl FavoritesQuery {
    fn parse(body: &[u8]) -> Result<Self, Refusal> {
        let root = Element::parse(body).map_err(|_| Refusal::Malformed)?;
        if root.name != "filter-files" || root.namespace.as_deref() != Some(NS_OC) {
            return Err(Refusal::Unsupported);
        }
        let child = |namespace: &str, name: &str| {
            root.children.iter().find_map(|node| match node {
                XMLNode::Element(element)
                    if element.name == name && element.namespace.as_deref() == Some(namespace) =>
                {
                    Some(element)
                }
                _ => None,
            })
        };
        let rules = child(NS_OC, "filter-rules").ok_or(Refusal::Unsupported)?;
        let mut favorites = false;
        for rule in rules.children.iter().filter_map(XMLNode::as_element) {
            if rule.name != "favorite" || rule.namespace.as_deref() != Some(NS_OC) {
                return Err(Refusal::Unsupported);
            }
            let value = rule.get_text().map(|text| text.trim().to_owned());
            match value.as_deref() {
                Some("1" | "true") => favorites = true,
                // "Not a favorite" would list nearly every file; nobody asks for it.
                _ => return Err(Refusal::Unsupported),
            }
        }
        if !favorites {
            return Err(Refusal::Unsupported);
        }
        Ok(Self {
            prop: child("DAV:", "prop").cloned(),
        })
    }

    /// The body of the internal PROPFIND: the requested `<D:prop>`, or `allprop` when the
    /// report names no properties.
    fn propfind_body(&self) -> Result<Bytes, Refusal> {
        let mut propfind = Element::new("propfind");
        propfind.prefix = Some("D".to_owned());
        propfind.namespace = Some("DAV:".to_owned());
        let mut namespaces = xmltree::Namespace::empty();
        namespaces.put("D", "DAV:");
        propfind.namespaces = Some(namespaces);
        match &self.prop {
            Some(prop) => propfind.children.push(XMLNode::Element(prop.clone())),
            None => {
                let mut allprop = Element::new("allprop");
                allprop.prefix = Some("D".to_owned());
                allprop.namespace = Some("DAV:".to_owned());
                propfind.children.push(XMLNode::Element(allprop));
            }
        }
        let mut xml = Vec::new();
        propfind.write(&mut xml).map_err(|_| Refusal::Malformed)?;
        Ok(Bytes::from(xml))
    }
}

/// Splits a multistatus document produced by dav-server into its root start tag, its content
/// and its end tag.
fn split_multistatus(xml: &str) -> Option<(&str, &str, &str)> {
    let open_at = xml.find("multistatus")?;
    let start = xml[..open_at].rfind('<')?;
    let open_end = start + xml[start..].find('>')? + 1;
    let close = xml.rfind("</")?;
    (close >= open_end).then(|| (&xml[start..open_end], &xml[open_end..close], &xml[close..]))
}

/// Serves a `REPORT` request of `identity` (see the module documentation).
pub async fn handle<B>(
    service: &DavService,
    identity: Arc<Identity>,
    request: Request<B>,
) -> Response<DavBody>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let (parts, body) = request.into_parts();
    if !path_is_clean(parts.uri.path()) {
        return simple(StatusCode::BAD_REQUEST);
    }
    let Ok(path) = DavPath::new(parts.uri.path()) else {
        return simple(StatusCode::BAD_REQUEST);
    };
    let body = match Limited::new(body, MAX_REPORT_BODY).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return simple(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let query = match FavoritesQuery::parse(&body) {
        Ok(query) => query,
        Err(Refusal::Malformed) => return simple(StatusCode::BAD_REQUEST),
        Err(Refusal::Unsupported) => return simple(StatusCode::NOT_IMPLEMENTED),
    };
    let Ok(propfind) = query.propfind_body() else {
        return simple(StatusCode::BAD_REQUEST);
    };

    let report = Method::from_bytes(b"REPORT").expect("valid method name");
    let ctx = Ctx::new(identity.clone(), RequestInfo::new(report));
    let favorites = match service.fs().favorites_below(&ctx, &path).await {
        Ok(favorites) => favorites,
        Err(FsError::NotFound) => return simple(StatusCode::NOT_FOUND),
        Err(FsError::Forbidden) => return simple(StatusCode::FORBIDDEN),
        Err(err) => {
            tracing::error!(error = ?err, "filter-files REPORT failed");
            return simple(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let Some(root_len) = resolve::dav_root_len(&identity, path.as_bytes()) else {
        return simple(StatusCode::NOT_FOUND);
    };
    let root = &path.as_bytes()[..root_len];
    let user_agent = parts.headers.get(header::USER_AGENT).cloned();

    let mut envelope: Option<(String, String)> = None;
    let mut responses = String::new();
    for (client, is_dir) in favorites {
        let Some(target) = resolve::dav_path(root, &client, is_dir) else {
            continue;
        };
        let mut lookup = Request::builder()
            .method("PROPFIND")
            .uri(target.as_url_string())
            .header("depth", "0")
            .header(header::CONTENT_TYPE, "application/xml; charset=utf-8");
        if let Some(user_agent) = &user_agent {
            lookup = lookup.header(header::USER_AGENT, user_agent);
        }
        let Ok(lookup) = lookup.body(Full::new(propfind.clone())) else {
            continue;
        };
        let answer = service.handle(identity.clone(), lookup).await;
        if answer.status() != StatusCode::MULTI_STATUS {
            // Gone from the disk since the metadata said it was there.
            continue;
        }
        let Ok(collected) = answer.into_body().collect().await else {
            continue;
        };
        let bytes = collected.to_bytes();
        let Some((open, content, close)) =
            std::str::from_utf8(&bytes).ok().and_then(split_multistatus)
        else {
            continue;
        };
        envelope.get_or_insert_with(|| (open.to_owned(), close.to_owned()));
        responses.push_str(content);
    }

    let (open, close) = envelope.unwrap_or_else(|| {
        (
            "<D:multistatus xmlns:D=\"DAV:\">".to_owned(),
            "</D:multistatus>".to_owned(),
        )
    });
    let xml = format!("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n{open}{responses}{close}\n");
    let mut response = xml_body(StatusCode::MULTI_STATUS, xml);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAVORITES: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<oc:filter-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
  <oc:filter-rules>
    <oc:favorite>1</oc:favorite>
  </oc:filter-rules>
  <d:prop>
    <d:getetag/>
    <oc:fileid/>
    <nc:has-preview/>
  </d:prop>
</oc:filter-files>"#;

    #[test]
    fn only_the_favorites_filter_is_served() {
        let query = FavoritesQuery::parse(FAVORITES.as_bytes()).unwrap();
        assert!(query.prop.is_some());
        let body = String::from_utf8(query.propfind_body().unwrap().to_vec()).unwrap();
        let reparsed = Element::parse(body.as_bytes()).unwrap();
        assert_eq!(reparsed.name, "propfind");
        assert_eq!(reparsed.namespace.as_deref(), Some("DAV:"));
        let prop = reparsed.get_child(("prop", "DAV:")).expect("prop kept");
        let names: Vec<(String, Option<String>)> = prop
            .children
            .iter()
            .filter_map(XMLNode::as_element)
            .map(|e| (e.name.clone(), e.namespace.clone()))
            .collect();
        assert_eq!(
            names,
            [
                ("getetag".to_owned(), Some("DAV:".to_owned())),
                ("fileid".to_owned(), Some(NS_OC.to_owned())),
                (
                    "has-preview".to_owned(),
                    Some(crate::props::NS_NC.to_owned())
                ),
            ],
            "{body}"
        );

        let tags = FAVORITES.replace(
            "<oc:favorite>1</oc:favorite>",
            "<oc:systemtag>4</oc:systemtag>",
        );
        assert_eq!(
            FavoritesQuery::parse(tags.as_bytes()),
            Err(Refusal::Unsupported)
        );
        let sync = r#"<d:sync-collection xmlns:d="DAV:"><d:sync-token/></d:sync-collection>"#;
        assert_eq!(
            FavoritesQuery::parse(sync.as_bytes()),
            Err(Refusal::Unsupported)
        );
        assert_eq!(FavoritesQuery::parse(b"not xml"), Err(Refusal::Malformed));
        let no_props = FAVORITES
            .replace("<d:prop>", "<d:x>")
            .replace("</d:prop>", "</d:x>");
        let query = FavoritesQuery::parse(no_props.as_bytes()).unwrap();
        let body = query.propfind_body().unwrap();
        assert!(String::from_utf8_lossy(&body).contains("allprop"));
    }

    #[test]
    fn multistatus_documents_split_at_the_root() {
        let xml = "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\" \
                   xmlns:oc=\"x\"><D:response>a</D:response></D:multistatus>";
        let (open, content, close) = split_multistatus(xml).unwrap();
        assert_eq!(open, "<D:multistatus xmlns:D=\"DAV:\" xmlns:oc=\"x\">");
        assert_eq!(content, "<D:response>a</D:response>");
        assert_eq!(close, "</D:multistatus>");
        assert_eq!(split_multistatus("<x/>"), None);
    }
}
