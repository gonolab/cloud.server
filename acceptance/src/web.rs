//! A tiny browser for the HTML flows (Login Flow v2 and the web admin UI).
//!
//! It keeps cookies, follows redirects, parses forms, and knows two ways to authenticate: an HTTP
//! Basic challenge and an HTML form with a password field. It does not run JavaScript.

use std::time::Duration;

use reqwest::{StatusCode, header::HeaderMap};
use scraper::{ElementRef, Html, Selector};
use url::Url;

use crate::Cred;

#[derive(Debug, Clone)]
pub struct Page {
    pub status: StatusCode,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct Button {
    pub name: Option<String>,
    pub value: String,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct Form {
    pub action: Url,
    pub method: String,
    /// Successful controls with their default values (hidden, text, checked boxes, ...).
    pub fields: Vec<(String, String)>,
    pub text_inputs: Vec<String>,
    pub password_inputs: Vec<String>,
    pub buttons: Vec<Button>,
}

impl Page {
    pub fn basic_challenge(&self) -> bool {
        self.status == StatusCode::UNAUTHORIZED
            && self
                .headers
                .get_all("www-authenticate")
                .iter()
                .any(|value| {
                    String::from_utf8_lossy(value.as_bytes())
                        .trim_start()
                        .to_ascii_lowercase()
                        .starts_with("basic")
                })
    }

    pub fn forms(&self) -> Vec<Form> {
        let document = Html::parse_document(&self.body);
        let form_selector = Selector::parse("form").expect("form selector");
        let control_selector =
            Selector::parse("input, button, select, textarea").expect("control selector");
        let option_selector = Selector::parse("option").expect("option selector");

        document
            .select(&form_selector)
            .map(|form| {
                let element = form.value();
                let action = element
                    .attr("action")
                    .filter(|action| !action.trim().is_empty())
                    .and_then(|action| self.url.join(action.trim()).ok())
                    .unwrap_or_else(|| self.url.clone());
                let method = element.attr("method").unwrap_or("get").to_ascii_uppercase();
                let mut parsed = Form {
                    action,
                    method,
                    fields: Vec::new(),
                    text_inputs: Vec::new(),
                    password_inputs: Vec::new(),
                    buttons: Vec::new(),
                };
                for control in form.select(&control_selector) {
                    add_control(&mut parsed, control, &option_selector);
                }
                parsed
            })
            .collect()
    }

    pub fn has_password_input(&self) -> bool {
        self.forms()
            .iter()
            .any(|form| !form.password_inputs.is_empty())
    }

    /// Links whose text matches one of `needles` (case-insensitive).
    pub fn link_matching(&self, needles: &[&str]) -> Option<Url> {
        let document = Html::parse_document(&self.body);
        let selector = Selector::parse("a[href]").expect("link selector");
        document.select(&selector).find_map(|link| {
            let text = link.text().collect::<String>().to_lowercase();
            needles
                .iter()
                .any(|needle| text.contains(needle))
                .then(|| link.value().attr("href"))
                .flatten()
                .and_then(|href| self.url.join(href).ok())
        })
    }

    pub fn describe(&self) -> String {
        let excerpt: String = self.body.chars().take(1500).collect();
        format!("{} {}\n  body: {excerpt}", self.status, self.url)
    }
}

fn add_control(form: &mut Form, control: ElementRef<'_>, option_selector: &Selector) {
    let element = control.value();
    let name = element.attr("name").map(str::to_owned);
    if element.attr("disabled").is_some() {
        return;
    }
    match element.name() {
        "input" => {
            let kind = element.attr("type").unwrap_or("text").to_ascii_lowercase();
            let value = element.attr("value").unwrap_or("").to_owned();
            match kind.as_str() {
                "password" => {
                    if let Some(name) = name {
                        form.password_inputs.push(name);
                    }
                }
                "submit" | "image" => form.buttons.push(Button {
                    name,
                    label: value.clone(),
                    value,
                }),
                "button" | "reset" | "file" => {}
                "checkbox" | "radio" => {
                    if let (Some(name), Some(_)) = (name, element.attr("checked")) {
                        let value = if value.is_empty() {
                            "on".to_owned()
                        } else {
                            value
                        };
                        form.fields.push((name, value));
                    }
                }
                "text" | "email" | "search" | "tel" | "url" => {
                    if let Some(name) = name {
                        form.text_inputs.push(name.clone());
                        form.fields.push((name, value));
                    }
                }
                _ => {
                    if let Some(name) = name {
                        form.fields.push((name, value));
                    }
                }
            }
        }
        "button" => {
            let kind = element
                .attr("type")
                .unwrap_or("submit")
                .to_ascii_lowercase();
            if kind == "submit" {
                form.buttons.push(Button {
                    name,
                    value: element.attr("value").unwrap_or("").to_owned(),
                    label: control.text().collect::<String>().trim().to_owned(),
                });
            }
        }
        "select" => {
            if let Some(name) = name {
                let options: Vec<_> = control.select(option_selector).collect();
                let selected = options
                    .iter()
                    .find(|option| option.value().attr("selected").is_some())
                    .or_else(|| options.first());
                if let Some(option) = selected {
                    let value = option
                        .value()
                        .attr("value")
                        .map(str::to_owned)
                        .unwrap_or_else(|| option.text().collect::<String>().trim().to_owned());
                    form.fields.push((name, value));
                }
            }
        }
        "textarea" => {
            if let Some(name) = name {
                form.fields.push((name, control.text().collect()));
            }
        }
        _ => {}
    }
}

const GRANT_WORDS: &[&str] = &[
    "grant",
    "allow",
    "approve",
    "authorize",
    "authorise",
    "confirm",
    "connect",
    "continue",
    "accept",
    "yes",
];
const DENY_WORDS: &[&str] = &["deny", "cancel", "reject", "decline", "abort", "no"];

fn button_score(button: &Button) -> i32 {
    let text = format!(
        "{} {} {}",
        button.label,
        button.value,
        button.name.as_deref().unwrap_or("")
    )
    .to_lowercase();
    let words: Vec<&str> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    if words.iter().any(|word| DENY_WORDS.contains(word)) {
        -1
    } else if GRANT_WORDS.iter().any(|grant| text.contains(grant)) {
        2
    } else {
        1
    }
}

/// Picks the form and button that most look like "grant access".
pub fn pick_consent(forms: &[Form]) -> Option<(Form, Option<Button>)> {
    let mut best: Option<(i32, Form, Option<Button>)> = None;
    for form in forms {
        let candidates: Vec<(i32, Option<Button>)> = if form.buttons.is_empty() {
            vec![(1, None)]
        } else {
            form.buttons
                .iter()
                .map(|button| (button_score(button), Some(button.clone())))
                .collect()
        };
        for (score, button) in candidates {
            if score > 0
                && best
                    .as_ref()
                    .is_none_or(|(best_score, _, _)| score > *best_score)
            {
                best = Some((score, form.clone(), button));
            }
        }
    }
    best.map(|(_, form, button)| (form, button))
}

/// What the driver did on the way to the current page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    BasicAuth,
    LoginForm,
    /// A non-login form submitted before the credentials were entered.
    FormBeforeLogin,
    /// A non-login form submitted after the credentials were entered.
    Consent,
    Link,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterLogin {
    /// Stop at the first page after authenticating (do not submit any further form).
    Stop,
    /// Keep submitting "grant"-looking forms after authenticating.
    Grant,
}

#[derive(Debug, Clone)]
pub struct Trace {
    pub steps: Vec<Step>,
    pub page: Page,
}

impl Trace {
    pub fn authenticated(&self) -> bool {
        self.steps
            .iter()
            .any(|step| matches!(step, Step::BasicAuth | Step::LoginForm))
    }

    pub fn consented_before_login(&self) -> bool {
        self.steps.contains(&Step::FormBeforeLogin)
    }

    pub fn consented_after_login(&self) -> bool {
        self.steps.contains(&Step::Consent)
    }

    /// The current page shows content that is neither an error nor a login prompt.
    pub fn granted_page(&self) -> bool {
        self.authenticated() && self.page.status.is_success() && !self.page.has_password_input()
    }
}

/// A cookie-keeping HTTP client that follows redirects.
pub struct Browser {
    client: reqwest::Client,
}

impl Browser {
    pub fn new(user_agent: &str) -> Browser {
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .timeout(Duration::from_secs(120))
            .user_agent(user_agent)
            .build()
            .expect("build browser client");
        Browser { client }
    }

    pub async fn get(&self, url: &Url, basic: Option<&Cred>) -> Page {
        let mut request = self.client.get(url.clone());
        if let Some(cred) = basic {
            request = request.basic_auth(&cred.user, Some(&cred.password));
        }
        page(request).await
    }

    pub async fn submit(
        &self,
        form: &Form,
        values: &[(String, String)],
        button: Option<&Button>,
    ) -> Page {
        let mut fields: Vec<(String, String)> = form
            .fields
            .iter()
            .filter(|(name, _)| {
                !values
                    .iter()
                    .any(|(override_name, _)| override_name == name)
            })
            .cloned()
            .collect();
        fields.extend(values.iter().cloned());
        if let Some(Button {
            name: Some(name),
            value,
            ..
        }) = button
        {
            fields.push((name.clone(), value.clone()));
        }
        let request = if form.method == "POST" {
            self.client.post(form.action.clone()).form(&fields)
        } else {
            let mut url = form.action.clone();
            url.query_pairs_mut().extend_pairs(fields.iter());
            self.client.get(url)
        };
        page(request).await
    }

    /// Opens `start` and logs in with `cred`, either through an HTTP Basic challenge or through
    /// an HTML login form. Forms seen before the login are submitted as "continue"; after the
    /// login the `after_login` policy decides.
    ///
    /// Returns `Err` when the server rejects the credentials (401 after Basic auth, or the login
    /// form shown again after submitting it).
    pub async fn login(
        &self,
        start: &Url,
        cred: &Cred,
        after_login: AfterLogin,
    ) -> Result<Trace, String> {
        let mut steps = Vec::new();
        let mut current = self.get(start, None).await;
        for _ in 0..10 {
            let authenticated = steps
                .iter()
                .any(|step| matches!(step, Step::BasicAuth | Step::LoginForm));
            if current.basic_challenge() {
                if authenticated {
                    return Err(format!(
                        "server rejected the Basic credentials\n{}",
                        current.describe()
                    ));
                }
                current = self.get(&current.url, Some(cred)).await;
                steps.push(Step::BasicAuth);
                if current.status == StatusCode::UNAUTHORIZED {
                    return Err(format!(
                        "server rejected the Basic credentials\n{}",
                        current.describe()
                    ));
                }
                continue;
            }
            let forms = current.forms();
            if let Some(form) = forms.iter().find(|form| !form.password_inputs.is_empty()) {
                if authenticated {
                    return Err(format!(
                        "login form shown again after submitting the credentials\n{}",
                        current.describe()
                    ));
                }
                let user_field = form
                    .text_inputs
                    .iter()
                    .find(|name| {
                        let name = name.to_lowercase();
                        ["user", "login", "name", "email", "account"]
                            .iter()
                            .any(|needle| name.contains(needle))
                    })
                    .or_else(|| form.text_inputs.first())
                    .cloned();
                let mut values = vec![(form.password_inputs[0].clone(), cred.password.clone())];
                if let Some(user_field) = user_field {
                    values.push((user_field, cred.user.clone()));
                }
                let button = form
                    .buttons
                    .iter()
                    .find(|button| button_score(button) > 0)
                    .cloned();
                current = self.submit(form, &values, button.as_ref()).await;
                steps.push(Step::LoginForm);
                continue;
            }
            if authenticated && after_login == AfterLogin::Stop {
                break;
            }
            if let Some((form, button)) = pick_consent(&forms) {
                current = self.submit(&form, &[], button.as_ref()).await;
                steps.push(if authenticated {
                    Step::Consent
                } else {
                    Step::FormBeforeLogin
                });
                continue;
            }
            if !authenticated
                && let Some(link) = current.link_matching(&["log in", "login", "sign in"])
            {
                current = self.get(&link, None).await;
                steps.push(Step::Link);
                continue;
            }
            break;
        }
        Ok(Trace {
            steps,
            page: current,
        })
    }

    /// Submits the "grant access" form on `page`, if there is one.
    pub async fn grant(&self, page: &Page) -> Option<Page> {
        let (form, button) = pick_consent(&page.forms())?;
        Some(self.submit(&form, &[], button.as_ref()).await)
    }
}

async fn page(request: reqwest::RequestBuilder) -> Page {
    let response = match request.send().await {
        Ok(response) => response,
        Err(err) => panic!("browser request failed: {err}"),
    };
    let status = response.status();
    let url = response.url().clone();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();
    Page {
        status,
        url,
        headers,
        body,
    }
}
