//! Web admin UI credentials: the admin UI uses a session login with the web login password;
//! device app passwords (of any scope) cannot open it.
//!
//! "Access granted" means the server answered 2xx with a page that is not a login form.

use gono_acceptance::{
    Cred, Ctx, require,
    web::{AfterLogin, Browser, Page},
};
use url::Url;

fn admin_url(ctx: &Ctx) -> Url {
    Url::parse(&ctx.url(&format!("{}/", ctx.cfg.admin_path))).expect("admin URL")
}

fn grants_access(page: &Page) -> bool {
    page.status.is_success() && !page.has_password_input()
}

/// Tries an app password against the admin UI both as a Basic header and through the login
/// form, and panics if either way opens it.
async fn assert_admin_refuses(ctx: &Ctx, cred: &Cred, label: &str) {
    let url = admin_url(ctx);

    let browser = Browser::new("gono-acceptance browser");
    let basic = browser.get(&url, Some(cred)).await;
    assert!(
        !grants_access(&basic),
        "the admin UI must not accept a {label} as Basic credentials\n{}",
        basic.describe()
    );

    let browser = Browser::new("gono-acceptance browser");
    if let Ok(trace) = browser.login(&url, cred, AfterLogin::Stop).await {
        assert!(
            !trace.granted_page(),
            "the admin UI must not accept a {label} at its login ({:?})\n{}",
            trace.steps,
            trace.page.describe()
        );
    }
}

#[tokio::test]
async fn admin_requires_authentication() {
    let Some(ctx) = Ctx::bare() else { return };
    let browser = Browser::new("gono-acceptance browser");
    let page = browser.get(&admin_url(&ctx), None).await;
    assert!(
        !grants_access(&page),
        "anonymous requests must get an error or a login form\n{}",
        page.describe()
    );
}

#[tokio::test]
async fn admin_accepts_the_web_password() {
    let Some(ctx) = Ctx::bare() else { return };
    let web = require!(ctx.web(), "GONO_ACCEPT_WEB_PASSWORD not set");
    let browser = Browser::new("gono-acceptance browser");
    let trace = match browser
        .login(&admin_url(&ctx), &web, AfterLogin::Stop)
        .await
    {
        Ok(trace) => trace,
        Err(err) => panic!("logging in to the admin UI with the web password failed: {err}"),
    };
    assert!(
        trace.granted_page(),
        "the web login password must open the admin UI ({:?})\n{}",
        trace.steps,
        trace.page.describe()
    );
}

/// Design change: the legacy admin UI accepted any app password of an admin user over Basic
/// auth. App passwords are device credentials and must not open it.
#[tokio::test]
async fn admin_rejects_full_scope_app_password() {
    let Some(ctx) = Ctx::bare() else { return };
    if ctx.cfg.web_password.as_deref() == Some(ctx.cfg.full.password.as_str()) {
        gono_acceptance::warn(
            "GONO_ACCEPT_WEB_PASSWORD equals the device password; this check expects them to differ",
        );
    }
    let full = ctx.cfg.full.clone();
    assert_admin_refuses(&ctx, &full, "full-scope app password").await;
}

/// Regression (legacy): the admin UI did not check app password scopes, so even a read-only
/// (`view`) app password of an admin user could manage users and app passwords.
#[tokio::test]
async fn regression_admin_rejects_view_scoped_app_password() {
    let Some(ctx) = Ctx::bare() else { return };
    let view = require!(ctx.view(), "GONO_ACCEPT_VIEW_PASSWORD not set");
    assert_admin_refuses(&ctx, &view, "read-only app password").await;
}
