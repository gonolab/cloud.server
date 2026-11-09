//! Tower layer that adds the Nextcloud `OC-*` response headers.
//!
//! [`crate::service::DavService`] attaches an [`OcInfo`] extension to responses about one
//! entry (PUT, MKCOL, MOVE, COPY, GET, HEAD). This layer turns it into headers:
//!
//! - `OC-ETag`: the entry's quoted ETag, equal to `ETag` and `DAV:getetag`;
//! - `OC-FileId`: the entry's `oc:id`;
//! - `X-NC-Permissions`: the entry's `oc:permissions`;
//! - `X-OC-MTime: accepted` when a PUT applied `X-OC-MTime`.
//!
//! It only adds headers; status and body pass through untouched.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::{HeaderName, HeaderValue, Request, Response};
use tower_layer::Layer;
use tower_service::Service;

use crate::service::OcInfo;

/// Adds the OC-* headers; see the [module documentation](self).
#[derive(Debug, Clone, Copy, Default)]
pub struct OcHeadersLayer;

impl<S> Layer<S> for OcHeadersLayer {
    type Service = OcHeaders<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OcHeaders { inner }
    }
}

/// The service produced by [`OcHeadersLayer`].
#[derive(Debug, Clone)]
pub struct OcHeaders<S> {
    inner: S,
}

impl<S, B, R> Service<Request<B>> for OcHeaders<S>
where
    S: Service<Request<B>, Response = Response<R>>,
    S::Future: Send + 'static,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let future = self.inner.call(request);
        Box::pin(async move {
            let mut response = future.await?;
            if let Some(info) = response.extensions_mut().remove::<OcInfo>() {
                add_headers(response.headers_mut(), &info);
            }
            Ok(response)
        })
    }
}

fn add_headers(headers: &mut http::HeaderMap, info: &OcInfo) {
    let mut insert = |name: &'static str, value: &str| {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(HeaderName::from_static(name), value);
        }
    };
    insert("oc-etag", &info.etag);
    if let Some(file_id) = &info.file_id {
        insert("oc-fileid", file_id);
    }
    insert("x-nc-permissions", info.permissions);
    if info.mtime_accepted {
        insert("x-oc-mtime", "accepted");
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;

    #[tokio::test]
    async fn turns_the_extension_into_headers() {
        let inner = tower_service_fn(|with_info: bool| {
            let mut response = Response::new("body");
            if with_info {
                response.extensions_mut().insert(OcInfo {
                    etag: "\"abc\"".into(),
                    file_id: Some("00000007ocinstance01".into()),
                    permissions: "GDNVW",
                    mtime_accepted: true,
                });
            }
            response
        });
        let mut service = OcHeadersLayer.layer(inner);
        let response = service.call(Request::new(true)).await.unwrap();
        assert_eq!(response.headers()["oc-etag"], "\"abc\"");
        assert_eq!(response.headers()["oc-fileid"], "00000007ocinstance01");
        assert_eq!(response.headers()["x-nc-permissions"], "GDNVW");
        assert_eq!(response.headers()["x-oc-mtime"], "accepted");
        assert_eq!(*response.body(), "body");
        assert!(response.extensions().get::<OcInfo>().is_none());

        let plain = service.call(Request::new(false)).await.unwrap();
        assert!(plain.headers().is_empty());
    }

    /// A minimal service that answers with `f(request body)`.
    fn tower_service_fn<F>(f: F) -> FnService<F> {
        FnService(f)
    }

    #[derive(Clone)]
    struct FnService<F>(F);

    impl<F> Service<Request<bool>> for FnService<F>
    where
        F: Fn(bool) -> Response<&'static str>,
    {
        type Response = Response<&'static str>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Infallible>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<bool>) -> Self::Future {
            std::future::ready(Ok((self.0)(*request.body())))
        }
    }
}
