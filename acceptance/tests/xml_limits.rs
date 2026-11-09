//! Limits on XML request bodies.
//!
//! WebDAV servers commonly parse request bodies into element trees recursively. Without a
//! nesting limit, one small request with a few thousand nested elements overflows the stack
//! and takes the whole server down, for every user. The server must refuse such bodies and keep
//! serving.
//!
//! This file is named to run last among the test binaries, and `scripts/run-legacy.sh` skips it:
//! the legacy server crashes on these requests, which would fail every test still running.

use gono_acceptance::{Ctx, dav::PROPFIND_STANDARD};

/// Nesting levels that overflow a 2 MiB thread stack in a recursive parser built in release
/// mode, in a body of about 9 KB, well inside the usual 64 KiB limit for XML bodies.
const DEEP: usize = 3000;

/// An XML body with `depth` levels: a DAV root element and `depth - 1` unclosed children.
fn deeply_nested(root: &str, depth: usize) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?><d:{root} xmlns:d="DAV:">{}"#,
        "<a>".repeat(depth - 1)
    )
}

#[tokio::test]
async fn deeply_nested_xml_bodies_are_refused_and_the_server_keeps_running() {
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let file = ctx.path("nested.txt");
    dav.write(&file, "x").await;

    dav.propfind(&file, "0", &deeply_nested("propfind", DEEP))
        .await
        .expect(&[400]);
    dav.proppatch(&file, &deeply_nested("propertyupdate", DEEP))
        .await
        .expect(&[400]);
    dav.send(
        dav.request("LOCK", &dav.url(&file))
            .header("Content-Type", "application/xml; charset=utf-8")
            .header("Timeout", "Second-60")
            .body(deeply_nested("lockinfo", DEEP)),
    )
    .await
    .expect(&[400]);
    dav.report(&ctx.path(""), &deeply_nested("filter-files", DEEP))
        .await
        .expect(&[400]);

    // Still serving, and nothing was locked or changed by the refused requests.
    dav.propfind(&file, "0", PROPFIND_STANDARD)
        .await
        .expect(&[207]);
    dav.put(&file, "y").await.expect_success();
    assert_eq!(dav.read(&file).await, b"y");
}
