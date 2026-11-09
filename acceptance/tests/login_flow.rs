//! Login Flow v2 and credential separation.
//!
//! The expected design: the browser step authenticates with the user's web login password, then
//! shows an explicit consent page; only after consent does the poll endpoint hand out a newly
//! minted app password, different for every device. The web login password itself is not a
//! device credential.

use gono_acceptance::{
    Cred, Ctx, Resp,
    dav::{PROPFIND_STANDARD, send},
    require, skip,
    web::{AfterLogin, Browser, pick_consent},
};
use url::Url;

struct Flow {
    token: String,
    endpoint: String,
    login: Url,
}

async fn start_flow(ctx: &Ctx, path: &str) -> Flow {
    let response = send(
        &ctx.http,
        ctx.http.post(ctx.url(path)).header(
            "User-Agent",
            format!("gono-acceptance device {}", gono_acceptance::random_id()),
        ),
    )
    .await;
    response.expect(&[200]);
    let body = response.json();
    let token = body["poll"]["token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let endpoint = body["poll"]["endpoint"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let login = body["login"].as_str().unwrap_or_default();
    assert!(
        !token.is_empty(),
        "Login Flow v2 init must return poll.token: {body}"
    );
    let login = Url::parse(login)
        .unwrap_or_else(|err| panic!("Login Flow v2 login URL {login:?} is invalid: {err}"));
    Flow {
        token,
        endpoint,
        login,
    }
}

async fn poll(ctx: &Ctx, flow: &Flow) -> Resp {
    send(
        &ctx.http,
        ctx.http
            .post(&flow.endpoint)
            .form(&[("token", flow.token.as_str())]),
    )
    .await
}

/// Revokes a minted app password through the Nextcloud OCS endpoint, if the server has one.
async fn revoke(ctx: &Ctx, user: &str, app_password: &str) {
    let cred = Cred::new(user, app_password);
    let _ = ctx
        .ocs("DELETE", "/ocs/v2.php/core/apppassword", Some(&cred))
        .await;
}

fn assert_same_origin(url: &str, base: &str, what: &str) {
    assert!(
        url.starts_with(&format!("{}/", base.trim_end_matches('/'))),
        "{what} {url:?} must be on the public origin {base:?}"
    );
}

#[tokio::test]
async fn login_flow_init_returns_poll_and_login_urls() {
    let Some(ctx) = Ctx::bare() else { return };
    for path in ["/index.php/login/v2", "/login/v2"] {
        let flow = start_flow(&ctx, path).await;
        assert_same_origin(&flow.endpoint, ctx.base_url(), "poll.endpoint");
        assert!(
            flow.endpoint.ends_with("/login/v2/poll"),
            "poll.endpoint {:?} must end with /login/v2/poll",
            flow.endpoint
        );
        assert_same_origin(flow.login.as_str(), ctx.base_url(), "login URL");
    }
}

#[tokio::test]
async fn login_flow_poll_is_pending_until_the_user_logs_in() {
    let Some(ctx) = Ctx::bare() else { return };
    let flow = start_flow(&ctx, "/index.php/login/v2").await;
    poll(&ctx, &flow).await.expect(&[404]);
    let unknown = Flow {
        token: "not-a-real-token".to_owned(),
        endpoint: flow.endpoint.clone(),
        login: flow.login.clone(),
    };
    poll(&ctx, &unknown).await.expect(&[404]);
}

#[tokio::test]
async fn login_flow_rejects_a_wrong_password() {
    let Some(ctx) = Ctx::bare() else { return };
    let flow = start_flow(&ctx, "/index.php/login/v2").await;
    let browser = Browser::new("gono-acceptance browser");
    let wrong = Cred::new(&ctx.cfg.full.user, "definitely-not-the-password");
    let result = browser.login(&flow.login, &wrong, AfterLogin::Grant).await;
    if let Ok(trace) = &result {
        assert!(
            !trace.granted_page() || !trace.authenticated(),
            "a wrong password must not be accepted: {:?}\n{}",
            trace.steps,
            trace.page.describe()
        );
    }
    poll(&ctx, &flow).await.expect(&[404]);
}

/// Regression (legacy): the browser step completed the flow as soon as Basic auth succeeded;
/// there was no consent page.
#[tokio::test]
async fn regression_login_flow_requires_explicit_consent() {
    let Some(ctx) = Ctx::bare() else { return };
    let web = require!(ctx.web(), "GONO_ACCEPT_WEB_PASSWORD not set");
    let flow = start_flow(&ctx, "/index.php/login/v2").await;
    let browser = Browser::new("gono-acceptance browser");
    let trace = match browser.login(&flow.login, &web, AfterLogin::Stop).await {
        Ok(trace) => trace,
        Err(err) => panic!("logging in with the web password failed: {err}"),
    };
    assert!(
        trace.authenticated(),
        "the login page never asked for credentials"
    );

    if trace.consented_before_login() {
        // Consent was given on a page before the credential prompt; the flow may finish now.
        let done = poll(&ctx, &flow).await;
        done.expect(&[200]);
        let password = done.json()["appPassword"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        revoke(&ctx, &web.user, &password).await;
        return;
    }

    let pending = poll(&ctx, &flow).await;
    if pending.code() == 200 {
        let password = pending.json()["appPassword"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if password != web.password {
            revoke(&ctx, &web.user, &password).await;
        }
    }
    assert_eq!(
        pending.code(),
        404,
        "authenticating must not complete the flow before the user consents\nafter login: {}\npoll: {}",
        trace.page.describe(),
        pending.describe()
    );
    assert!(
        pick_consent(&trace.page.forms()).is_some(),
        "after login the user must see a consent form\n{}",
        trace.page.describe()
    );

    let granted = browser
        .grant(&trace.page)
        .await
        .expect("consent form disappeared");
    assert!(granted.status.is_success(), "{}", granted.describe());
    let done = poll(&ctx, &flow).await;
    done.expect(&[200]);
    let password = done.json()["appPassword"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    revoke(&ctx, &web.user, &password).await;
}

async fn complete_flow(ctx: &Ctx, web: &Cred) -> serde_json::Value {
    let flow = start_flow(ctx, "/index.php/login/v2").await;
    let browser = Browser::new("gono-acceptance browser");
    let trace = match browser.login(&flow.login, web, AfterLogin::Grant).await {
        Ok(trace) => trace,
        Err(err) => panic!("logging in with the web password failed: {err}"),
    };
    let done = poll(ctx, &flow).await;
    assert_eq!(
        done.code(),
        200,
        "the flow must complete after login and consent ({:?})\n{}\n{}",
        trace.steps,
        trace.page.describe(),
        done.describe()
    );
    poll(ctx, &flow).await.expect(&[404]);
    done.json()
}

/// Regression (legacy): the poll endpoint returned the password the user typed in the browser
/// instead of a newly minted app password.
#[tokio::test]
async fn regression_login_flow_mints_a_new_app_password() {
    let Some(ctx) = Ctx::bare() else { return };
    let web = require!(ctx.web(), "GONO_ACCEPT_WEB_PASSWORD not set");

    let first = complete_flow(&ctx, &web).await;
    let first_password = first["appPassword"].as_str().unwrap_or_default().to_owned();
    assert_eq!(first["loginName"], web.user.as_str(), "{first}");
    assert_eq!(
        first["server"]
            .as_str()
            .map(|server| server.trim_end_matches('/')),
        Some(ctx.base_url()),
        "{first}"
    );
    assert!(
        first_password != web.password,
        "Login Flow v2 must mint a new app password instead of returning the login password"
    );
    assert!(
        first_password.len() >= 32,
        "app password looks weak ({} characters)",
        first_password.len()
    );

    let minted = Cred::new(&web.user, &first_password);
    ctx.dav_as(&minted)
        .propfind("", "0", PROPFIND_STANDARD)
        .await
        .expect(&[207]);

    let second = complete_flow(&ctx, &web).await;
    let second_password = second["appPassword"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    revoke(&ctx, &web.user, &second_password).await;
    assert!(
        first_password != second_password,
        "every device must get its own app password"
    );
    revoke(&ctx, &web.user, &first_password).await;
}

#[tokio::test]
async fn web_password_is_not_a_device_credential() {
    let Some(ctx) = Ctx::bare() else { return };
    let web = require!(ctx.web(), "GONO_ACCEPT_WEB_PASSWORD not set");
    if web.password == ctx.cfg.full.password {
        skip(
            "GONO_ACCEPT_WEB_PASSWORD equals the device password (legacy server); nothing to tell apart",
        );
        return;
    }
    ctx.dav_as(&web)
        .propfind("", "0", PROPFIND_STANDARD)
        .await
        .expect(&[401]);
    ctx.ocs("GET", "/ocs/v2.php/cloud/user", Some(&web))
        .await
        .expect(&[401]);
}
