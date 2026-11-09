//! `gono-cloud serve`.

use std::{path::Path, sync::Arc, time::Duration};

use anyhow::Context;
use dav_server::{DavHandler, DavMethodSet};
use gono_server_core::{
    Config,
    db::{self, OpenMode},
    locks::LockStore,
    meta::MetaStore,
    settings,
    storage::DataLayout,
    users,
};
use gono_server_dav::{DavService, ScopedFs, locks::SqliteLs};
use gono_server_nextcloud::{
    chunking::ChunkedUploads,
    notify_push::{self, Hub, PushSettings},
};
use tokio::net::TcpListener;

use super::{load_config, refuse_root_on_foreign_install};
use crate::{
    admin::{Admin, ServerInfo},
    app::{self, AppState},
    auth::Authenticator,
    janitor::Janitor,
    logging::{self, Destination},
    ratelimit::RateLimiter,
    shutdown,
    web::Web,
};

/// Runs the HTTP server until SIGTERM or Ctrl-C.
pub async fn run(config_path: &Path) -> anyhow::Result<()> {
    let config = load_config(config_path)?;
    refuse_root_on_foreign_install(&config)?;
    let destination = config
        .logging
        .file
        .clone()
        .map_or(Destination::Stdout, Destination::File);
    let _log_guard = logging::init(config.logging.level, destination)?;

    let config_path = std::path::absolute(config_path).unwrap_or_else(|_| config_path.into());
    let result = serve(config, config_path).await;
    if let Err(err) = &result {
        // Also record fatal errors in the log, which may be a file.
        tracing::error!("{err:#}");
    }
    result
}

async fn serve(config: Config, config_path: std::path::PathBuf) -> anyhow::Result<()> {
    let started_at = db::unix_now();
    for warning in config.warnings() {
        tracing::warn!("{warning}");
    }

    let pool = db::connect(&config.db, OpenMode::MustExist)
        .await
        .context("open database")?;
    db::migrate(&pool)
        .await
        .context("apply database migrations")?;
    if users::count(&pool).await? == 0 {
        tracing::warn!("no user accounts exist; run `gono-cloud init`");
    }
    let layout = DataLayout::new(&config.storage.data_dir);
    layout.open().context("open data directory")?;
    let case_insensitive = match layout.is_case_insensitive() {
        Ok(true) => {
            tracing::warn!(
                data_dir = %layout.root().display(),
                "the data directory is on a case-insensitive file system: names that differ \
                 only in case (Report.pdf, report.pdf) cannot coexist, although clients on \
                 other systems may create them; a case-sensitive file system is recommended"
            );
            Some(true)
        }
        Ok(false) => Some(false),
        Err(err) => {
            tracing::warn!(error = %err, "cannot tell whether the data directory ignores case");
            None
        }
    };
    let purged = LockStore::new(pool.clone())
        .purge_expired(db::unix_now())
        .await?;
    if purged > 0 {
        tracing::debug!(purged, "removed expired WebDAV locks");
    }

    let bind = config.server.bind;
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("listen on {bind}"))?;
    let local_addr = listener.local_addr().context("read listener address")?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        address = %local_addr,
        base_url = %config.server.base_url,
        "listening"
    );

    // notify_push announces changes committed from now on; older ones are history.
    let push = if config.notify_push.enabled {
        let watermark = MetaStore::new(pool.clone())
            .latest_change_id()
            .await
            .context("read the change log")?;
        Some(Hub::new(
            PushSettings::from_config(&config.notify_push),
            watermark,
        ))
    } else {
        None
    };
    let mut meta = MetaStore::new(pool.clone());
    if let Some(hub) = &push {
        meta = meta.with_sink(hub.clone());
    }
    let feed = push
        .clone()
        .map(|hub| tokio::spawn(notify_push::run_feed(hub, meta.clone())));

    let dav = dav_service(
        Duration::from_secs(config.webdav.max_lock_timeout_secs),
        layout,
        meta,
    )
    .await?;
    let uploads = ChunkedUploads::new(dav.fs().clone(), LockStore::new(pool.clone()));
    let janitor = Janitor {
        db: pool.clone(),
        uploads: uploads.clone(),
    }
    .spawn();
    let auth = Arc::new(Authenticator::new(
        pool.clone(),
        Arc::new(RateLimiter::new()),
    ));
    // The HTML sign-in shares the failed-attempt limiter of device authentication.
    let web = Arc::new(Web::new(
        pool.clone(),
        auth.limiter().clone(),
        &config.server.base_url,
    ));
    let admin = if config.admin.enabled {
        let info = ServerInfo {
            started_at,
            instance_id: dav.fs().instance_id().to_owned(),
            bind: local_addr,
            trusted_proxies: config.server.trusted_proxies.clone(),
            config_path,
            log: format!(
                "{} → {}",
                config.logging.level.as_str(),
                config
                    .logging
                    .file
                    .as_ref()
                    .map_or_else(|| "stdout".to_owned(), |file| file.display().to_string())
            ),
            data_dir: config.storage.data_dir.clone(),
            db_path: config.db.path.clone(),
            case_insensitive,
            lock_timeout_secs: config.webdav.max_lock_timeout_secs,
            push: push.as_ref().map(|hub| *hub.settings()),
            warnings: config.warnings(),
        };
        tracing::info!(path = %config.admin.path, "web admin UI enabled");
        Some(Arc::new(Admin::new(&config.admin.path, info)))
    } else {
        None
    };
    let state = AppState {
        db: pool.clone(),
        auth,
        dav,
        uploads,
        web,
        base_url: Arc::new(config.server.base_url.clone()),
        flow_starts: Arc::new(RateLimiter::new()),
        trusted_proxies: Arc::new(config.server.trusted_proxies.clone()),
        push: push.clone(),
        admin,
    };
    let on_signal = {
        let push = push.clone();
        move || {
            if let Some(hub) = push {
                hub.shut_down();
            }
        }
    };
    let result = shutdown::serve(listener, app::router(state), on_signal).await;
    if let Some(hub) = &push {
        hub.shut_down();
    }
    if let Some(feed) = feed {
        feed.abort();
    }
    janitor.abort();
    pool.close().await;
    tracing::info!("stopped");
    result
}

/// Builds the one `DavHandler` of the process and the service around it. Every metadata
/// change goes through `meta`, which publishes it to its sink.
pub(crate) async fn dav_service(
    max_lock_timeout: Duration,
    layout: DataLayout,
    meta: MetaStore,
) -> anyhow::Result<DavService> {
    let pool = meta.pool().clone();
    let instance_id = settings::instance_id(&pool)
        .await
        .context("read the instance id")?;
    let fs = ScopedFs::new(layout, meta, instance_id);
    let locks = SqliteLs::new(LockStore::new(pool), max_lock_timeout);
    // REPORT (filter-files) is served outside dav-server; CalDAV and CardDAV are not offered.
    let mut methods = DavMethodSet::all();
    for method in [
        dav_server::DavMethod::Report,
        dav_server::DavMethod::MkCalendar,
        dav_server::DavMethod::MkAddressbook,
    ] {
        methods.remove(method);
    }
    let handler = DavHandler::builder()
        .filesystem(Box::new(fs.clone()))
        .locksystem(locks)
        .methods(methods)
        .build_handler();
    Ok(DavService::new(handler, fs))
}
