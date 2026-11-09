//! End-to-end tests of the `gono-cloud` binary.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const PASSWORD: &str = "correct horse battery staple";

fn gono_cloud() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gono-cloud"));
    command
        .env_remove("GONO_CLOUD_CONFIG")
        .env_remove("GONO_CLOUD_LOG");
    command
}

fn run(command: &mut Command) -> Output {
    command.output().expect("run gono-cloud")
}

fn run_with_stdin(command: &mut Command, input: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gono-cloud");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A temporary installation directory with a config file.
struct Instance {
    dir: tempfile::TempDir,
    addr: SocketAddr,
}

impl Instance {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let addr = free_port();
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                r#"
                [server]
                bind = "{addr}"
                base_url = "http://{addr}"

                [storage]
                data_dir = "data"

                [db]
                path = "db/gono-cloud.db"
                "#
            ),
        )
        .unwrap();
        Self { dir, addr }
    }

    fn config(&self) -> PathBuf {
        self.dir.path().join("config.toml")
    }

    fn db(&self) -> PathBuf {
        self.dir.path().join("db/gono-cloud.db")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = gono_cloud();
        command.arg("--config").arg(self.config()).args(args);
        command
    }

    fn init(&self) -> Output {
        run_with_stdin(
            &mut self.command(&["init", "--password-stdin"]),
            &format!("{PASSWORD}\n"),
        )
    }
}

fn free_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn example_config() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml")
}

#[test]
fn help_lists_every_subcommand() {
    let output = run(gono_cloud().arg("--help"));
    assert!(output.status.success());
    let help = text(&output.stdout);
    for command in ["serve", "init", "config", "user", "app-password", "rescan"] {
        assert!(help.contains(command), "missing {command}:\n{help}");
    }
    assert!(help.contains("GONO_CLOUD_CONFIG"), "{help}");
}

#[test]
fn config_check_accepts_the_example() {
    let output = run(gono_cloud()
        .args(["config", "check", "--config"])
        .arg(example_config()));
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(stdout.contains("Configuration OK"), "{stdout}");
    assert!(stdout.contains("127.0.0.1:16102"), "{stdout}");
    assert!(!stdout.contains("warning"), "{stdout}");
}

#[test]
fn config_check_reads_the_path_from_the_environment() {
    let output = run(gono_cloud()
        .args(["config", "check"])
        .env("GONO_CLOUD_CONFIG", example_config()));
    assert!(output.status.success(), "{}", text(&output.stderr));
}

#[test]
fn config_check_reports_every_invalid_value() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        r#"
        [server]
        bind = "0.0.0.0:16102"
        base_url = "https://cloud.example.com/sub"

        [storage]
        data_dir = "data"

        [db]
        path = "gono-cloud.db"

        [notify_push]
        ping_interval_secs = 0
        "#,
    )
    .unwrap();

    let output = run(gono_cloud()
        .args(["config", "check", "--config"])
        .arg(&config));
    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    for key in [
        "server.bind",
        "server.base_url",
        "notify_push.ping_interval_secs",
    ] {
        assert!(stderr.contains(key), "missing {key}:\n{stderr}");
    }
}

#[test]
fn config_check_rejects_unknown_keys() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let example = std::fs::read_to_string(example_config()).unwrap();
    std::fs::write(&config, example.replace("[db]", "[db]\nmax_conections = 4")).unwrap();

    let output = run(gono_cloud()
        .args(["config", "check", "--config"])
        .arg(&config));
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("max_conections"));
}

#[test]
fn missing_config_files_get_a_hint() {
    let output = run(gono_cloud().args(["config", "check", "--config", "/nonexistent.toml"]));
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("--config"));
}

#[test]
fn init_creates_the_first_admin_exactly_once() {
    let instance = Instance::new();

    let output = instance.init();
    assert!(output.status.success(), "{}", text(&output.stderr));
    let stdout = text(&output.stdout);
    assert!(stdout.contains("admin"), "{stdout}");
    assert!(instance.db().exists());
    assert!(instance.dir.path().join("data").is_dir());
    for stream in [&output.stdout, &output.stderr] {
        assert!(!text(stream).contains(PASSWORD), "password leaked");
    }

    let again = instance.init();
    assert!(!again.status.success());
    assert!(
        text(&again.stderr).contains("already contains users"),
        "{}",
        text(&again.stderr)
    );
}

#[test]
fn init_needs_a_terminal_or_password_stdin() {
    let instance = Instance::new();
    let output = run(instance.command(&["init"]).stdin(Stdio::null()));
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("--password-stdin"));
}

#[test]
fn init_rejects_weak_passwords_without_echoing_them() {
    let instance = Instance::new();
    let output = run_with_stdin(
        &mut instance.command(&["init", "--password-stdin"]),
        "short\n",
    );
    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    assert!(stderr.contains("at least 8 characters"), "{stderr}");
    assert!(!stderr.contains("short\n") && !stderr.contains("\"short\""));
}

#[test]
fn serve_requires_an_initialized_database() {
    let instance = Instance::new();
    let output = run(&mut instance.command(&["serve"]));
    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("gono-cloud init"));
    assert!(
        !instance.db().exists(),
        "serve must not create the database"
    );
}

/// Rows of the admin's `files` table, as `(rel_path, size)`, ordered by path.
async fn file_rows(instance: &Instance) -> Vec<(String, i64)> {
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", instance.db().display()))
        .await
        .unwrap();
    let rows =
        sqlx::query_as("SELECT rel_path, size FROM files WHERE owner_id = 1 ORDER BY rel_path")
            .fetch_all(&pool)
            .await
            .unwrap();
    pool.close().await;
    rows
}

#[tokio::test]
async fn rescan_reconciles_changes_made_behind_the_servers_back() {
    let instance = Instance::new();
    assert!(instance.init().status.success());
    let files = instance.dir.path().join("data/files/1");
    std::fs::create_dir_all(files.join("docs")).unwrap();
    std::fs::write(files.join("docs/a.txt"), "hello").unwrap();
    std::fs::write(files.join("Cafe\u{301}.txt"), "nfd").unwrap();

    let dry = run(&mut instance.command(&["rescan", "admin", "--dry-run"]));
    assert!(dry.status.success(), "{}", text(&dry.stderr));
    let report = text(&dry.stdout);
    assert!(report.contains("Dry run"), "{report}");
    assert!(
        report.contains("would rename to NFC: /Caf\u{e9}.txt"),
        "{report}"
    );
    assert!(report.contains("would add:    /docs"), "{report}");
    assert!(
        file_rows(&instance).await.is_empty(),
        "a dry run changes nothing"
    );
    assert!(
        std::fs::read_dir(&files)
            .unwrap()
            .any(|entry| entry.unwrap().file_name() == "Cafe\u{301}.txt")
    );

    let done = run(&mut instance.command(&["rescan", "admin"]));
    assert!(done.status.success(), "{}", text(&done.stderr));
    let report = text(&done.stdout);
    assert!(
        report.contains("renamed to NFC:   /Caf\u{e9}.txt"),
        "{report}"
    );
    assert_eq!(
        file_rows(&instance).await,
        [
            (String::new(), 8),
            ("Caf\u{e9}.txt".to_owned(), 3),
            ("docs".to_owned(), 5),
            ("docs/a.txt".to_owned(), 5),
        ]
    );
    let again = run(&mut instance.command(&["rescan", "--all"]));
    assert!(text(&again.stdout).contains("Everything was up to date."));

    std::fs::remove_file(files.join("docs/a.txt")).unwrap();
    let scoped = run(&mut instance.command(&["rescan", "admin", "--path", "/docs"]));
    assert!(scoped.status.success(), "{}", text(&scoped.stderr));
    assert!(text(&scoped.stdout).contains("removed:  /docs/a.txt"));
    assert_eq!(file_rows(&instance).await[0], (String::new(), 3));

    let missing = run(&mut instance.command(&["rescan", "admin", "--path", "/nope"]));
    assert_eq!(missing.status.code(), Some(1));
    assert!(text(&missing.stderr).contains("does not exist"));
}

/// The next text frame within ten seconds (pings are answered while reading).
#[cfg(unix)]
async fn next_text(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Option<String> {
    use futures_util::StreamExt as _;
    use tokio_tungstenite::tungstenite::Message;
    loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => return Some(text.to_string()),
            Ok(Some(Ok(_))) => {}
            _ => return None,
        }
    }
}

/// A rescan run next to the server reaches notify_push clients through the change log.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn rescan_changes_are_pushed_by_a_running_server() {
    use futures_util::SinkExt as _;
    use tokio_tungstenite::tungstenite::Message;

    let instance = Instance::new();
    assert!(instance.init().status.success());
    let add = run(&mut instance.command(&["app-password", "add", "admin", "--label", "push"]));
    let password = app_password_from(&add);
    let mut child = instance
        .command(&["serve"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let addr = instance.addr;
    wait_for_health(&mut child, addr);

    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/push/ws"))
        .await
        .unwrap();
    socket.send(Message::text("admin")).await.unwrap();
    socket.send(Message::text(password)).await.unwrap();
    assert_eq!(
        next_text(&mut socket).await.as_deref(),
        Some("authenticated")
    );

    std::fs::write(instance.dir.path().join("data/files/1/dropped.txt"), "x").unwrap();
    let rescan = run(&mut instance.command(&["rescan", "admin"]));
    assert!(rescan.status.success(), "{}", text(&rescan.stderr));
    assert_eq!(next_text(&mut socket).await.as_deref(), Some("notify_file"));

    child.kill().unwrap();
    child.wait().unwrap();
}

/// Extracts the value of the `App password: <value>` line.
fn app_password_from(output: &Output) -> String {
    let stdout = text(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("App password: "))
        .unwrap_or_else(|| panic!("no app password in output:\n{stdout}"))
        .to_owned()
}

#[test]
fn users_can_be_managed() {
    let instance = Instance::new();
    assert!(instance.init().status.success());

    let add = run_with_stdin(
        &mut instance.command(&[
            "user",
            "add",
            "alice",
            "--display-name",
            "Alice Example",
            "--password-stdin",
        ]),
        &format!("{PASSWORD}\n"),
    );
    assert!(add.status.success(), "{}", text(&add.stderr));
    assert!(instance.dir.path().join("data/files/2").is_dir());
    assert!(instance.dir.path().join("data/uploads/2").is_dir());

    let duplicate = run_with_stdin(
        &mut instance.command(&["user", "add", "alice", "--password-stdin"]),
        &format!("{PASSWORD}\n"),
    );
    assert!(!duplicate.status.success());
    assert!(text(&duplicate.stderr).contains("already exists"));

    for args in [
        &["user", "disable", "alice"][..],
        &["user", "enable", "alice"],
    ] {
        let output = run(&mut instance.command(args));
        assert!(
            output.status.success(),
            "{args:?}: {}",
            text(&output.stderr)
        );
    }
    let set_password = run_with_stdin(
        &mut instance.command(&["user", "set-password", "alice", "--password-stdin"]),
        "another good password\n",
    );
    assert!(
        set_password.status.success(),
        "{}",
        text(&set_password.stderr)
    );

    let list = run(&mut instance.command(&["user", "list"]));
    assert!(list.status.success());
    let listing = text(&list.stdout);
    assert!(listing.contains("Alice Example"), "{listing}");
    assert!(
        listing
            .lines()
            .any(|line| line.starts_with("1 ") && line.contains("admin"))
    );

    std::fs::write(instance.dir.path().join("data/files/2/kept.txt"), "kept").unwrap();
    let delete = run(&mut instance.command(&["user", "delete", "alice"]));
    assert!(delete.status.success(), "{}", text(&delete.stderr));
    assert!(!instance.dir.path().join("data/files/2").exists());
    let deleted: Vec<_> = std::fs::read_dir(instance.dir.path().join("data/deleted"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(deleted.len(), 1);
    assert!(deleted[0].join("files/kept.txt").is_file());

    let missing = run(&mut instance.command(&["user", "delete", "alice"]));
    assert!(!missing.status.success());
    assert!(text(&missing.stderr).contains("does not exist"));

    // The only admin can be neither disabled nor deleted.
    for args in [
        &["user", "disable", "admin"][..],
        &["user", "delete", "admin"],
    ] {
        let output = run(&mut instance.command(args));
        assert!(!output.status.success(), "{args:?}");
        assert!(
            text(&output.stderr).contains("last enabled admin"),
            "{args:?}: {}",
            text(&output.stderr)
        );
    }
}

#[test]
fn app_passwords_are_shown_once_and_can_be_revoked() {
    let instance = Instance::new();
    assert!(instance.init().status.success());

    let add = run(&mut instance.command(&[
        "app-password",
        "add",
        "admin",
        "--label",
        "phone",
        "--scope",
        "/Photos=/Media/Photos:view",
        "--scope",
        "/Inbox=/Inbox:full",
    ]));
    assert!(add.status.success(), "{}", text(&add.stderr));
    let password = app_password_from(&add);
    assert_eq!(password.len(), 29, "{password}");
    assert!(!text(&add.stderr).contains(&password));

    let list = run(&mut instance.command(&["app-password", "list", "admin"]));
    assert!(list.status.success());
    let listing = text(&list.stdout);
    assert!(listing.contains("phone"), "{listing}");
    assert!(listing.contains("/Photos=/Media/Photos:view"), "{listing}");
    assert!(listing.contains("/Inbox=/Inbox:full"), "{listing}");
    assert!(
        !listing.contains(&password),
        "list must never show the value"
    );

    let nested = run(&mut instance.command(&[
        "app-password",
        "add",
        "admin",
        "--label",
        "nested",
        "--scope",
        "/=/:view",
        "--scope",
        "/a=/a:full",
    ]));
    assert!(!nested.status.success());
    assert!(
        text(&nested.stderr).contains("nested"),
        "{}",
        text(&nested.stderr)
    );

    let full = run(&mut instance.command(&["app-password", "add", "admin", "--label", "laptop"]));
    assert!(full.status.success());
    assert!(
        text(&full.stdout).contains("/=/:full"),
        "{}",
        text(&full.stdout)
    );

    let delete = run(&mut instance.command(&["app-password", "delete", "admin", "1"]));
    assert!(delete.status.success(), "{}", text(&delete.stderr));
    let again = run(&mut instance.command(&["app-password", "delete", "admin", "1"]));
    assert!(!again.status.success());

    let db = std::fs::read(instance.db()).unwrap();
    assert!(
        !db.windows(password.len())
            .any(|window| window == password.as_bytes()),
        "the plaintext app password must not be stored"
    );
}

#[cfg(unix)]
#[test]
fn serve_answers_health_checks_and_stops_on_sigterm() {
    let instance = Instance::new();
    assert!(instance.init().status.success());

    let mut child = instance
        .command(&["serve"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let response = wait_for_health(&mut child, instance.addr);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("ok\n"), "{response}");

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());

    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        assert!(
            Instant::now() < deadline,
            "server did not stop after SIGTERM"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().unwrap();
    let logs = text(&output.stdout);
    assert!(output.status.success(), "{logs}\n{}", text(&output.stderr));
    assert!(logs.contains("listening"), "{logs}");
    assert!(logs.contains("received SIGTERM"), "{logs}");
    assert!(!logs.contains(PASSWORD));
}

/// Polls `GET /healthz` until the server answers.
#[cfg(unix)]
fn wait_for_health(child: &mut Child, addr: SocketAddr) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("server exited early with {status}");
        }
        if let Some(response) = http_get(addr, "/healthz") {
            return response;
        }
        assert!(
            Instant::now() < deadline,
            "server did not come up on {addr}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
fn http_get(addr: SocketAddr, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}
