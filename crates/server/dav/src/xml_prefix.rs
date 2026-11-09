//! Tower layer that writes the `DAV:` namespace with the prefix `d`, as Nextcloud does.
//!
//! dav-server (and the REPORT built on its output, [`crate::report`]) writes `DAV:` elements
//! as `<D:multistatus xmlns:D="DAV:">`. That is valid XML, but NextcloudKit (the Nextcloud iOS
//! app) looks elements up by their literal qualified names, `d:multistatus`, `d:response`,
//! `d:href`, ..., the way SabreDAV writes them. With `D:` it finds no entries and shows every
//! folder as empty. This layer renames the prefix `D` to `d` in the XML bodies of WebDAV
//! responses:
//!
//! - element names `<D:x>` and `</D:x>`, attribute names `D:x="..."` and the declaration
//!   `xmlns:D="..."`, in every tag;
//! - nothing in text content, attribute values, comments, CDATA sections or processing
//!   instructions, so property values and dead properties pass unchanged (a literal `<` cannot
//!   occur in text; XML escapes it).
//!
//! Renaming a prefix consistently keeps the document equivalent. Only a dead property that
//! declares both `d` and `D` on one element could clash, which no client does.
//!
//! The rewrite applies to responses with an XML content type, except to `GET` and `HEAD`,
//! whose bodies are file contents. It streams: bytes are held back only while the next byte
//! decides them (at most `xmlns:D`), and since `D` and `d` are one byte each, the body keeps
//! its length and `Content-Length` stays valid.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use http::{Method, Request, Response, header};
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use tower_layer::Layer;
use tower_service::Service;

/// Renames the `D` prefix to `d` in XML response bodies; see the [module documentation](self).
#[derive(Debug, Clone, Copy, Default)]
pub struct DavPrefixLayer;

impl<S> Layer<S> for DavPrefixLayer {
    type Service = DavPrefix<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DavPrefix { inner }
    }
}

/// The service produced by [`DavPrefixLayer`].
#[derive(Debug, Clone)]
pub struct DavPrefix<S> {
    inner: S,
}

impl<S, B, R> Service<Request<B>> for DavPrefix<S>
where
    S: Service<Request<B>, Response = Response<R>>,
    S::Future: Send + 'static,
{
    type Response = Response<PrefixBody<R>>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let file_content = matches!(*request.method(), Method::GET | Method::HEAD);
        let future = self.inner.call(request);
        Box::pin(async move {
            let response = future.await?;
            let rewrite = !file_content && is_xml(response.headers());
            Ok(response.map(|inner| PrefixBody {
                inner,
                rewriter: rewrite.then(PrefixRewriter::default),
                done: false,
            }))
        })
    }
}

fn is_xml(headers: &http::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|essence| essence.trim().to_ascii_lowercase())
        .is_some_and(|essence| essence == "application/xml" || essence == "text/xml")
}

pin_project! {
    /// A response body that passes through [`PrefixRewriter`] when the response is XML.
    pub struct PrefixBody<B> {
        #[pin]
        inner: B,
        rewriter: Option<PrefixRewriter>,
        done: bool,
    }
}

impl<B> Body for PrefixBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        let Some(rewriter) = this.rewriter.as_mut() else {
            return this.inner.poll_frame(cx);
        };
        if *this.done {
            return Poll::Ready(None);
        }
        loop {
            match ready!(this.inner.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        let mut out = Vec::with_capacity(data.len() + XMLNS_D.len());
                        rewriter.feed(&data, &mut out);
                        if !out.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                        }
                    }
                    // Trailers: WebDAV responses have none, and the few held-back bytes
                    // follow with the end of the body.
                    Err(frame) => return Poll::Ready(Some(Ok(frame))),
                },
                Some(Err(err)) => return Poll::Ready(Some(Err(err))),
                None => {
                    *this.done = true;
                    let mut out = Vec::new();
                    rewriter.finish(&mut out);
                    return Poll::Ready((!out.is_empty()).then(|| Ok(Frame::data(out.into()))));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        if self.rewriter.is_some() {
            self.done
        } else {
            self.inner.is_end_stream()
        }
    }

    fn size_hint(&self) -> SizeHint {
        // The rewrite replaces single bytes, so the length does not change.
        self.inner.size_hint()
    }
}

/// Where the rewriter is in the document.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Character data between tags.
    #[default]
    Text,
    /// After `<` or `</`; `pending` holds them, and a `D` that may start a prefix.
    Open,
    /// After `<!`; `pending` holds the bytes until the kind of markup is known.
    Bang,
    /// In an element name.
    Name,
    /// In a tag, outside names and values.
    Tag,
    /// At the start of an attribute name; `pending` holds it while it may still become
    /// `D:...` or `xmlns:D`.
    AttrStart,
    /// In the rest of an attribute name.
    Attr,
    /// In an attribute value delimited by this quote.
    Value(u8),
    /// In `<!-- ... -->`.
    Comment,
    /// In `<![CDATA[ ... ]]>`.
    Cdata,
    /// In `<? ... ?>`.
    Pi,
    /// In another `<! ... >` declaration.
    Declaration,
}

/// Streaming renamer of the `D` prefix; see the [module documentation](self).
#[derive(Debug, Default)]
pub struct PrefixRewriter {
    state: State,
    /// Bytes held back until the next byte decides whether they change.
    pending: Vec<u8>,
    /// The last two bytes copied in a comment, CDATA section or processing instruction, to
    /// find its end.
    tail: [u8; 2],
}

const XMLNS_D: &[u8] = b"xmlns:D";

fn ends_name(byte: u8) -> bool {
    matches!(byte, b'=' | b'>' | b'/') || byte.is_ascii_whitespace()
}

impl PrefixRewriter {
    /// Rewrites the next part of the body into `out`.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) {
        for &byte in input {
            self.byte(byte, out);
        }
    }

    /// Writes the bytes still held back at the end of the body.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.pending);
    }

    fn byte(&mut self, byte: u8, out: &mut Vec<u8>) {
        match self.state {
            State::Text => {
                if byte == b'<' {
                    self.pending.push(byte);
                    self.state = State::Open;
                } else {
                    out.push(byte);
                }
            }
            State::Open => self.open(byte, out),
            State::Bang => self.bang(byte, out),
            State::Name | State::Attr => {
                if ends_name(byte) {
                    self.state = State::Tag;
                    self.tag(byte, out);
                } else {
                    out.push(byte);
                }
            }
            State::Tag => self.tag(byte, out),
            State::AttrStart => self.attr_start(byte, out),
            State::Value(quote) => {
                out.push(byte);
                if byte == quote {
                    self.state = State::Tag;
                }
            }
            State::Comment => self.until(byte, b"--", out),
            State::Cdata => self.until(byte, b"]]", out),
            State::Pi => self.until(byte, b"?", out),
            State::Declaration => {
                out.push(byte);
                if byte == b'>' {
                    self.state = State::Text;
                }
            }
        }
    }

    /// After `<`, `</`, `<D` or `</D`: renames the element name's prefix `D`.
    fn open(&mut self, byte: u8, out: &mut Vec<u8>) {
        let held_d = self.pending.last() == Some(&b'D');
        match byte {
            b':' if held_d => {
                if let Some(last) = self.pending.last_mut() {
                    *last = b'd';
                }
                out.append(&mut self.pending);
                out.push(byte);
                self.state = State::Name;
            }
            b'/' if self.pending == b"<" => self.pending.push(byte),
            b'D' if !held_d => self.pending.push(byte),
            b'!' if self.pending == b"<" => {
                self.pending.push(byte);
                self.state = State::Bang;
            }
            b'?' if self.pending == b"<" => {
                out.append(&mut self.pending);
                out.push(byte);
                self.tail = [0, 0];
                self.state = State::Pi;
            }
            _ => {
                out.append(&mut self.pending);
                self.state = State::Name;
                self.byte(byte, out);
            }
        }
    }

    /// After `<!`: a comment, a CDATA section or another declaration.
    fn bang(&mut self, byte: u8, out: &mut Vec<u8>) {
        self.pending.push(byte);
        let next = match self.pending.as_slice() {
            b"<!-" => return,
            b"<!--" => State::Comment,
            b"<![" => State::Cdata,
            _ if byte == b'>' => State::Text,
            _ => State::Declaration,
        };
        out.append(&mut self.pending);
        self.tail = [0, 0];
        self.state = next;
    }

    /// In a tag, outside names and values.
    fn tag(&mut self, byte: u8, out: &mut Vec<u8>) {
        match byte {
            b'"' | b'\'' => {
                out.push(byte);
                self.state = State::Value(byte);
            }
            b'>' => {
                out.push(byte);
                self.state = State::Text;
            }
            _ if ends_name(byte) => out.push(byte),
            _ => {
                self.state = State::AttrStart;
                self.attr_start(byte, out);
            }
        }
    }

    /// At the start of an attribute name: renames `D:...` and `xmlns:D`.
    fn attr_start(&mut self, byte: u8, out: &mut Vec<u8>) {
        if ends_name(byte) {
            if self.pending == XMLNS_D {
                self.pending[XMLNS_D.len() - 1] = b'd';
            }
            out.append(&mut self.pending);
            self.state = State::Tag;
            self.tag(byte, out);
            return;
        }
        self.pending.push(byte);
        match self.pending.as_slice() {
            b"D" => return,
            b"D:" => self.pending[0] = b'd',
            held if XMLNS_D.starts_with(held) => return,
            _ => {}
        }
        out.append(&mut self.pending);
        self.state = State::Attr;
    }

    /// Copies `byte` and leaves the comment, CDATA section or processing instruction at the
    /// `>` that follows `end`.
    fn until(&mut self, byte: u8, end: &[u8], out: &mut Vec<u8>) {
        out.push(byte);
        if byte == b'>' && self.tail.ends_with(end) {
            self.state = State::Text;
        }
        self.tail = [self.tail[1], byte];
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use http_body_util::{BodyExt as _, Full, StreamBody};

    use super::*;

    fn rewrite(input: &str) -> String {
        let mut rewriter = PrefixRewriter::default();
        let mut out = Vec::new();
        rewriter.feed(input.as_bytes(), &mut out);
        rewriter.finish(&mut out);
        String::from_utf8(out).unwrap()
    }

    /// The same input fed one byte at a time, so that every split point is exercised.
    fn rewrite_bytewise(input: &str) -> String {
        let mut rewriter = PrefixRewriter::default();
        let mut out = Vec::new();
        for byte in input.as_bytes() {
            rewriter.feed(std::slice::from_ref(byte), &mut out);
        }
        rewriter.finish(&mut out);
        String::from_utf8(out).unwrap()
    }

    fn check(input: &str, expected: &str) {
        assert_eq!(rewrite(input), expected, "whole input");
        assert_eq!(rewrite_bytewise(input), expected, "byte by byte");
        assert_eq!(input.len(), expected.len());
    }

    #[test]
    fn renames_the_prefix_of_dav_elements() {
        check(
            r#"<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:" xmlns:oc="http://owncloud.org/ns"><D:response><D:href>/remote.php/dav/files/a/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype><oc:fileid>1</oc:fileid></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"#,
            r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/remote.php/dav/files/a/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><oc:fileid>1</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#,
        );
        check(
            "<D:error xmlns:D=\"DAV:\">\n  <D:propfind-finite-depth />\n</D:error>\n",
            "<d:error xmlns:d=\"DAV:\">\n  <d:propfind-finite-depth />\n</d:error>\n",
        );
    }

    #[test]
    fn leaves_text_values_comments_and_cdata_alone() {
        let untouched = [
            // Text: `<` is always escaped, so only names that look like prefixes remain.
            "<d:x>D:a xmlns:D=\"DAV:\" &lt;D:b&gt; > D:</d:x>",
            // Attribute values, either quote.
            r#"<x:a xmlns:x="urn:x" v='xmlns:D="DAV:" &lt;D:y' w="D:z">t</x:a>"#,
            // Comments, CDATA and processing instructions.
            "<!-- <D:x> xmlns:D= --><![CDATA[<D:y xmlns:D=\"DAV:\">]]><?pi <D:z> ?><a/>",
            // Other prefixes that merely start with D, and names that end in D.
            r#"<DAV:x xmlns:DAV="DAV:" xmlns:Dx="urn:x" xmlns:D2="urn:y"><Dx:y/><aD:z/></DAV:x>"#,
            // A declaration.
            "<!DOCTYPE x><x/>",
        ];
        for input in untouched {
            check(input, input);
        }
    }

    #[test]
    fn renames_prefixed_attributes_and_declarations_everywhere() {
        check(
            r#"<x:a xmlns:x="urn:x" D:foo="1" xmlns:D="DAV:"><D:b xmlns:D = 'DAV:'/></x:a>"#,
            r#"<x:a xmlns:x="urn:x" d:foo="1" xmlns:d="DAV:"><d:b xmlns:d = 'DAV:'/></x:a>"#,
        );
    }

    #[test]
    fn keeps_bytes_held_back_at_the_end() {
        for input in ["<", "<D", "</D", "<!-", "<a xmlns:D", "<a D"] {
            check(input, input);
        }
    }

    async fn through_layer(method: Method, content_type: &str, chunks: &[&'static str]) -> String {
        let content_type = content_type.to_owned();
        let chunks: Vec<&'static str> = chunks.to_vec();
        let inner = tower_service_fn(move |_request: Request<()>| {
            let stream = futures_util::stream::iter(
                chunks
                    .clone()
                    .into_iter()
                    .map(|chunk| Ok::<_, Infallible>(Frame::data(Bytes::from(chunk)))),
            );
            Response::builder()
                .header(header::CONTENT_TYPE, content_type.clone())
                .body(StreamBody::new(stream))
                .unwrap()
        });
        let mut service = DavPrefixLayer.layer(inner);
        let request = Request::builder().method(method).body(()).unwrap();
        let response = service.call(request).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn the_layer_rewrites_xml_responses_except_file_contents() {
        let propfind = Method::from_bytes(b"PROPFIND").unwrap();
        // Split inside `<D:` and inside `xmlns:D`.
        let chunks = [
            "<D:multistatus xml",
            "ns:D=\"DAV:\"><",
            "D:response/></D:multistatus>",
        ];
        assert_eq!(
            through_layer(propfind.clone(), "application/xml; charset=utf-8", &chunks).await,
            r#"<d:multistatus xmlns:d="DAV:"><d:response/></d:multistatus>"#
        );
        assert_eq!(
            through_layer(propfind, "text/plain", &chunks).await,
            chunks.concat(),
            "not XML"
        );
        assert_eq!(
            through_layer(Method::GET, "application/xml", &chunks).await,
            chunks.concat(),
            "a file's content"
        );
    }

    #[tokio::test]
    async fn the_layer_keeps_the_size_hint() {
        let inner = tower_service_fn(|_request: Request<()>| {
            Response::builder()
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Full::new(Bytes::from_static(b"<D:a xmlns:D=\"DAV:\"/>")))
                .unwrap()
        });
        let mut service = DavPrefixLayer.layer(inner);
        let request = Request::builder()
            .method(Method::from_bytes(b"PROPFIND").unwrap())
            .body(())
            .unwrap();
        let body = service.call(request).await.unwrap().into_body();
        assert_eq!(body.size_hint().exact(), Some(21));
        assert_eq!(
            body.collect().await.unwrap().to_bytes(),
            "<d:a xmlns:d=\"DAV:\"/>"
        );
    }

    fn tower_service_fn<F, R>(f: F) -> FnService<F>
    where
        F: FnMut(Request<()>) -> Response<R>,
    {
        FnService(f)
    }

    struct FnService<F>(F);

    impl<F, R> Service<Request<()>> for FnService<F>
    where
        F: FnMut(Request<()>) -> Response<R>,
    {
        type Response = Response<R>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Response<R>, Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<()>) -> Self::Future {
            std::future::ready(Ok((self.0)(request)))
        }
    }
}
