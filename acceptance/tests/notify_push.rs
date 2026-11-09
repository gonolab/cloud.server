//! notify_push: capabilities, WebSocket authentication (app password and pre-auth token), and
//! file change notifications.
//!
//! notify_push messages are not tied to a request, so a change made by another test of the same
//! user would satisfy a "notification received" check. The tests in this binary therefore run one
//! at a time, and cargo runs test binaries one after another.

use std::time::Duration;

use gono_acceptance::{
    Ctx,
    dav::send,
    push::{Frame, Push, is_file_notification, notified_file_ids},
    random_id, require,
};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// How long a socket must stay silent before a test triggers its own change.
const QUIET: Duration = Duration::from_secs(1);
/// How long to wait before concluding that a notification was (correctly) not sent.
const ABSENCE: Duration = Duration::from_secs(3);

async fn connect(ctx: &Ctx) -> Push {
    let url = ctx.push_websocket_url().await;
    let mut push = Push::authenticated(
        &url,
        &ctx.cfg.full.user,
        &ctx.cfg.full.password,
        ctx.cfg.push_timeout,
    )
    .await;
    push.drain(QUIET).await;
    push
}

async fn expect_notification(ctx: &Ctx, push: &mut Push, after: &str) -> String {
    match push.wait_file_notification(ctx.cfg.push_timeout).await {
        Some(message) => {
            push.drain(QUIET).await;
            message
        }
        None => panic!(
            "no notify_file message within {:?} after {after}",
            ctx.cfg.push_timeout
        ),
    }
}

#[tokio::test]
async fn capabilities_advertise_notify_push() {
    let Some(ctx) = Ctx::bare() else { return };
    let capabilities = ctx.capabilities().await;
    let notify = &capabilities["notify_push"];
    let types: Vec<&str> = notify["type"]
        .as_array()
        .map(|types| types.iter().filter_map(|value| value.as_str()).collect())
        .unwrap_or_default();
    assert!(
        types.contains(&"files"),
        "notify_push.type must include files: {notify}"
    );
    let websocket = notify["endpoints"]["websocket"]
        .as_str()
        .unwrap_or_default();
    assert!(
        websocket.starts_with("ws://") || websocket.starts_with("wss://"),
        "notify_push.endpoints.websocket must be a WebSocket URL: {notify}"
    );
    let pre_auth = notify["endpoints"]["pre_auth"].as_str().unwrap_or_default();
    assert!(
        pre_auth.starts_with("http://") || pre_auth.starts_with("https://"),
        "notify_push.endpoints.pre_auth must be an HTTP URL: {notify}"
    );
}

#[tokio::test]
async fn websocket_authenticates_with_an_app_password() {
    let _serial = SERIAL.lock().await;
    let Some(ctx) = Ctx::bare() else { return };
    connect(&ctx).await.close().await;
}

#[tokio::test]
async fn websocket_rejects_bad_credentials() {
    let _serial = SERIAL.lock().await;
    let Some(ctx) = Ctx::bare() else { return };
    let url = ctx.push_websocket_url().await;
    let (push, reply) = Push::login(
        &url,
        &ctx.cfg.full.user,
        "definitely-not-the-password",
        ctx.cfg.push_timeout,
    )
    .await
    .unwrap_or_else(|err| panic!("{err}"));
    match &reply {
        Frame::Text(text) => assert!(
            text.starts_with("err"),
            "bad credentials must be answered with an error, got {text:?}"
        ),
        Frame::Closed(_) => {}
        Frame::Timeout => panic!(
            "no reply to bad credentials within {:?}",
            ctx.cfg.push_timeout
        ),
    }
    push.close().await;
}

async fn pre_auth_token(ctx: &Ctx) -> String {
    let capabilities = ctx.capabilities().await;
    let url = capabilities["notify_push"]["endpoints"]["pre_auth"]
        .as_str()
        .expect("notify_push.endpoints.pre_auth")
        .to_owned();
    let response = send(
        &ctx.http,
        ctx.http
            .post(&url)
            .basic_auth(&ctx.cfg.full.user, Some(&ctx.cfg.full.password)),
    )
    .await;
    response.expect(&[200]);
    let token = response.text().trim().to_owned();
    assert!(
        token.len() >= 32,
        "pre-auth token looks weak: {} characters",
        token.len()
    );
    token
}

#[tokio::test]
async fn pre_auth_requires_authentication() {
    let Some(ctx) = Ctx::bare() else { return };
    let capabilities = ctx.capabilities().await;
    let url = capabilities["notify_push"]["endpoints"]["pre_auth"]
        .as_str()
        .expect("notify_push.endpoints.pre_auth")
        .to_owned();
    send(&ctx.http, ctx.http.post(&url)).await.expect(&[401]);
}

#[tokio::test]
async fn pre_auth_token_is_single_use() {
    let _serial = SERIAL.lock().await;
    let Some(ctx) = Ctx::bare() else { return };
    let url = ctx.push_websocket_url().await;
    let token = pre_auth_token(&ctx).await;

    let first = Push::authenticated(&url, "", &token, ctx.cfg.push_timeout).await;
    let (second, reply) = Push::login(&url, "", &token, ctx.cfg.push_timeout)
        .await
        .unwrap_or_else(|err| panic!("{err}"));
    assert_ne!(
        reply,
        Frame::Text("authenticated".to_owned()),
        "a pre-auth token must only work once"
    );
    first.close().await;
    second.close().await;
}

#[tokio::test]
async fn put_triggers_a_file_notification() {
    let _serial = SERIAL.lock().await;
    let Some(ctx) = Ctx::new().await else { return };
    let mut push = connect(&ctx).await;
    ctx.dav().write(&ctx.path("pushed.txt"), "push me").await;
    expect_notification(&ctx, &mut push, "PUT").await;
    push.close().await;
}

#[tokio::test]
async fn mkcol_copy_and_move_trigger_file_notifications() {
    let _serial = SERIAL.lock().await;
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    dav.write(&ctx.path("source.txt"), "source").await;
    let mut push = connect(&ctx).await;

    dav.create_dir(&ctx.path("dir")).await;
    expect_notification(&ctx, &mut push, "MKCOL").await;
    dav.copy(&ctx.path("source.txt"), &ctx.path("dir/copy.txt"), None)
        .await
        .expect(&[201]);
    expect_notification(&ctx, &mut push, "COPY").await;
    dav.mv(&ctx.path("source.txt"), &ctx.path("dir/moved.txt"), None)
        .await
        .expect(&[201]);
    expect_notification(&ctx, &mut push, "MOVE").await;
    push.close().await;
}

#[tokio::test]
async fn chunked_upload_triggers_a_file_notification() {
    let _serial = SERIAL.lock().await;
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let mut push = connect(&ctx).await;
    let upload = format!("acc-{}", random_id());
    let destination = dav.url(&ctx.path("chunked.txt"));
    let session = |method: &str, rel: &str| {
        dav.request(method, &dav.upload_url(rel))
            .header("Destination", &destination)
            .header("OC-Total-Length", "5")
    };
    dav.send(session("MKCOL", &upload)).await.expect(&[201]);
    dav.send(session("PUT", &format!("{upload}/00001")).body("hello"))
        .await
        .expect(&[201, 204]);
    dav.send(session("MOVE", &format!("{upload}/.file")))
        .await
        .expect(&[201]);
    expect_notification(&ctx, &mut push, "chunked upload MOVE").await;
    push.close().await;
}

/// Regression (legacy): a standalone DELETE never reached the WebSocket because the deleted
/// file id could no longer be resolved to a path when filtering the notification.
#[tokio::test]
async fn regression_delete_triggers_a_file_notification() {
    let _serial = SERIAL.lock().await;
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let mut push = connect(&ctx).await;
    dav.write(&ctx.path("doomed.txt"), "doomed").await;
    expect_notification(&ctx, &mut push, "PUT").await;

    dav.delete(&ctx.path("doomed.txt")).await.expect(&[204]);
    expect_notification(&ctx, &mut push, "DELETE").await;
    push.close().await;
}

#[tokio::test]
async fn listen_notify_file_id_reports_the_changed_file() {
    let _serial = SERIAL.lock().await;
    let Some(ctx) = Ctx::new().await else { return };
    let dav = ctx.dav();
    let mut push = connect(&ctx).await;
    push.send_text("listen notify_file_id")
        .await
        .unwrap_or_else(|err| panic!("{err}"));
    push.drain(QUIET).await;

    dav.write(&ctx.path("with-id.txt"), "id").await;
    let message = expect_notification(&ctx, &mut push, "PUT").await;
    let fileid = dav.fileid(&ctx.path("with-id.txt")).await;
    match notified_file_ids(&message) {
        Some(ids) => assert!(
            ids.contains(&fileid),
            "notify_file_id must list the changed file id {fileid}: {message}"
        ),
        None => gono_acceptance::warn(&format!(
            "server answered `listen notify_file_id` with {message:?}; file ids are optional"
        )),
    }
    push.close().await;
}

#[tokio::test]
async fn changes_are_not_pushed_to_other_users() {
    let _serial = SERIAL.lock().await;
    let Some(ctx) = Ctx::new().await else { return };
    let user2 = require!(ctx.user2(), "GONO_ACCEPT_USER2/PASSWORD2 not set");
    let url = ctx.push_websocket_url().await;
    let mut own = connect(&ctx).await;
    let mut other =
        Push::authenticated(&url, &user2.user, &user2.password, ctx.cfg.push_timeout).await;
    other.drain(QUIET).await;

    ctx.dav().write(&ctx.path("private.txt"), "private").await;
    expect_notification(&ctx, &mut own, "PUT").await;
    let leaked = other.wait_file_notification(ABSENCE).await;
    assert!(
        leaked.is_none(),
        "another user's socket received {leaked:?} for a change it cannot see"
    );
    own.close().await;
    other.close().await;
}

#[test]
fn notification_parsing() {
    assert!(is_file_notification("notify_file"));
    assert!(is_file_notification("notify_file_id [1,2]"));
    assert!(!is_file_notification("notify_activity"));
    assert_eq!(
        notified_file_ids("notify_file_id [12, 34]"),
        Some(vec!["12".to_owned(), "34".to_owned()])
    );
}
