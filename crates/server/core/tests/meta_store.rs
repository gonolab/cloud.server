//! MetaStore against a real SQLite database: file ids, ETag and size propagation, dead
//! properties, and subtree operations on names that `LIKE` would get wrong.

use gono_server_core::{
    RelPath, Username,
    config::DbConfig,
    db::{self, OpenMode, Pool},
    meta::{DeadProp, DiskStat, MetaStore, PropChange},
    users::{self, NewUser},
};

struct Fixture {
    _dir: tempfile::TempDir,
    store: MetaStore,
    owner: i64,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let config = DbConfig {
        path: dir.path().join("gono-cloud.db"),
        max_connections: 4,
        busy_timeout_secs: 5,
    };
    let pool = db::connect(&config, OpenMode::CreateIfMissing)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let owner = add_user(&pool, "alice").await;
    let store = MetaStore::new(pool);
    store
        .adopt(owner, &[(RelPath::root(), dir_stat())])
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        owner,
    }
}

async fn add_user(pool: &Pool, name: &str) -> i64 {
    let username = Username::new(name).unwrap();
    users::create(
        pool,
        &NewUser {
            username: &username,
            display_name: name,
            password_hash: "x",
            is_admin: false,
        },
        |_| Ok(()),
    )
    .await
    .unwrap()
}

fn p(path: &str) -> RelPath {
    RelPath::parse(path).unwrap()
}

fn dir_stat() -> DiskStat {
    DiskStat {
        is_dir: true,
        mtime_ns: 1,
        size: 0,
    }
}

fn file_stat(size: u64) -> DiskStat {
    DiskStat {
        is_dir: false,
        mtime_ns: 1_000,
        size,
    }
}

fn dead(name: &str, value: &str) -> DeadProp {
    DeadProp {
        namespace: "urn:test".into(),
        name: name.into(),
        xml: format!("<x:{name} xmlns:x=\"urn:test\">{value}</x:{name}>").into_bytes(),
    }
}

impl Fixture {
    async fn mkdir(&self, path: &str) -> i64 {
        self.store
            .record_mkdir(self.owner, &p(path), 5)
            .await
            .unwrap()
            .id
    }

    async fn write(&self, path: &str, size: u64) -> i64 {
        self.store
            .record_write(self.owner, &p(path), file_stat(size))
            .await
            .unwrap()
            .id
    }

    async fn etag(&self, path: &str) -> String {
        self.store
            .get(self.owner, &p(path))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("no row for {path}"))
            .etag
    }

    async fn etags(&self, paths: &[&str]) -> Vec<String> {
        let mut etags = Vec::new();
        for path in paths {
            etags.push(self.etag(path).await);
        }
        etags
    }

    async fn size(&self, path: &str) -> u64 {
        self.store
            .get(self.owner, &p(path))
            .await
            .unwrap()
            .unwrap()
            .size
    }

    async fn exists(&self, path: &str) -> bool {
        self.store
            .get(self.owner, &p(path))
            .await
            .unwrap()
            .is_some()
    }

    async fn tag(&self, path: &str) -> i64 {
        let row = self.store.get(self.owner, &p(path)).await.unwrap().unwrap();
        self.store
            .patch_dead_props(row.id, &[PropChange::Set(dead("marker", "keep-me"))])
            .await
            .unwrap();
        row.id
    }

    async fn marker(&self, id: i64) -> Option<Vec<u8>> {
        self.store
            .dead_prop(id, "urn:test", "marker")
            .await
            .unwrap()
    }

    async fn changes(&self) -> Vec<(String, String, Option<String>)> {
        sqlx::query_as(
            "SELECT operation, rel_path, old_rel_path FROM change_log WHERE owner_id = ?1 \
             ORDER BY id",
        )
        .bind(self.owner)
        .fetch_all(self.store.pool())
        .await
        .unwrap()
    }
}

fn all_changed(before: &[String], after: &[String]) -> bool {
    before.iter().zip(after).all(|(old, new)| old != new)
}

#[tokio::test]
async fn file_ids_are_numeric_stable_and_never_reused() {
    let f = fixture().await;
    f.mkdir("d").await;
    let id = f.write("d/a.txt", 3).await;
    assert_eq!(f.write("d/a.txt", 5).await, id, "overwrite keeps the id");

    let moved = f
        .store
        .record_move(f.owner, &p("d/a.txt"), &p("d/b.txt"), file_stat(5))
        .await
        .unwrap();
    assert_eq!(moved.id, id, "move keeps the id");

    let copy = f
        .store
        .record_copy(
            f.owner,
            &p("d/b.txt"),
            &p("d/c.txt"),
            &[(RelPath::root(), file_stat(5))],
        )
        .await
        .unwrap();
    assert_ne!(copy.id, id, "copy allocates a new id");

    f.store.record_delete(f.owner, &p("d/b.txt")).await.unwrap();
    let recreated = f.write("d/b.txt", 1).await;
    assert!(recreated > copy.id, "ids of deleted entries are not reused");
}

#[tokio::test]
async fn file_etags_change_with_every_write() {
    let f = fixture().await;
    f.write("same.txt", 4).await;
    let first = f.etag("same.txt").await;
    // Same size and mtime: only the per-write nonce distinguishes the versions.
    f.write("same.txt", 4).await;
    assert_ne!(f.etag("same.txt").await, first);
}

#[tokio::test]
async fn every_change_propagates_to_all_ancestors() {
    let f = fixture().await;
    f.mkdir("d1").await;
    f.mkdir("d1/d2").await;
    f.mkdir("other").await;
    f.write("d1/d2/f.txt", 10).await;
    let ancestors = ["", "d1", "d1/d2"];

    let mut before = f.etags(&ancestors).await;
    f.write("d1/d2/f.txt", 12).await;
    let mut after = f.etags(&ancestors).await;
    assert!(all_changed(&before, &after), "modify: {before:?} {after:?}");

    before = after;
    f.write("d1/d2/new.txt", 1).await;
    after = f.etags(&ancestors).await;
    assert!(all_changed(&before, &after), "create");

    before = after;
    f.mkdir("d1/d2/sub").await;
    after = f.etags(&ancestors).await;
    assert!(all_changed(&before, &after), "mkdir");

    before = after;
    f.store
        .record_copy(
            f.owner,
            &p("d1/d2/f.txt"),
            &p("d1/d2/g.txt"),
            &[(RelPath::root(), file_stat(12))],
        )
        .await
        .unwrap();
    after = f.etags(&ancestors).await;
    assert!(all_changed(&before, &after), "copy");

    before = after;
    f.store
        .record_delete(f.owner, &p("d1/d2/new.txt"))
        .await
        .unwrap();
    after = f.etags(&ancestors).await;
    assert!(all_changed(&before, &after), "delete");

    let both = ["", "d1", "d1/d2", "other"];
    let before = f.etags(&both).await;
    f.store
        .record_move(f.owner, &p("d1/d2/g.txt"), &p("other/g.txt"), file_stat(12))
        .await
        .unwrap();
    let after = f.etags(&both).await;
    assert!(all_changed(&before, &after), "move updates both parents");

    let unrelated = f.etag("other").await;
    f.write("d1/x.txt", 1).await;
    assert_eq!(f.etag("other").await, unrelated, "siblings are not touched");
}

#[tokio::test]
async fn folder_sizes_are_recursive() {
    let f = fixture().await;
    f.mkdir("dir").await;
    f.mkdir("dir/sub").await;
    f.write("dir/a.txt", 5).await;
    f.write("dir/sub/b.txt", 7).await;
    assert_eq!(f.size("dir").await, 12);
    assert_eq!(f.size("").await, 12);

    f.write("dir/a.txt", 2).await;
    assert_eq!(f.size("dir").await, 9);

    f.mkdir("elsewhere").await;
    f.store
        .record_move(f.owner, &p("dir/sub"), &p("elsewhere/sub"), dir_stat())
        .await
        .unwrap();
    assert_eq!(f.size("dir").await, 2);
    assert_eq!(f.size("elsewhere").await, 7);
    assert_eq!(f.size("elsewhere/sub").await, 7);

    f.store
        .record_copy(
            f.owner,
            &p("elsewhere/sub"),
            &p("dir/copy"),
            &[(RelPath::root(), dir_stat()), (p("b.txt"), file_stat(7))],
        )
        .await
        .unwrap();
    assert_eq!(f.size("dir/copy").await, 7);
    assert_eq!(f.size("dir").await, 9);

    f.store.record_delete(f.owner, &p("dir")).await.unwrap();
    assert_eq!(f.size("").await, 7);
}

/// Regression for the legacy `LIKE 'photos_1/%'` bug: `_` and `%` are ordinary characters.
#[tokio::test]
async fn wildcard_characters_do_not_leak_into_siblings() {
    let f = fixture().await;
    for (doomed, sibling) in [("photos_1", "photosX1"), ("a%", "ab"), ("c_d", "c%d")] {
        f.mkdir(doomed).await;
        f.write(&format!("{doomed}/inner.txt"), 1).await;
        f.mkdir(sibling).await;
        f.write(&format!("{sibling}/x.txt"), 1).await;
        let id = f.tag(&format!("{sibling}/x.txt")).await;

        f.store.record_delete(f.owner, &p(doomed)).await.unwrap();
        assert!(!f.exists(&format!("{doomed}/inner.txt")).await);
        assert!(
            f.exists(&format!("{sibling}/x.txt")).await,
            "{sibling} after deleting {doomed}"
        );
        assert!(
            f.marker(id).await.is_some(),
            "dead property of {sibling}/x.txt"
        );
    }
}

#[tokio::test]
async fn moving_a_wildcard_name_leaves_siblings_alone() {
    let f = fixture().await;
    f.mkdir("photos_1").await;
    f.write("photos_1/inner.txt", 1).await;
    f.mkdir("photosX1").await;
    f.write("photosX1/x.txt", 1).await;
    let id = f.tag("photosX1/x.txt").await;

    f.store
        .record_move(f.owner, &p("photos_1"), &p("renamed"), dir_stat())
        .await
        .unwrap();
    assert!(f.exists("renamed/inner.txt").await);
    assert!(!f.exists("photos_1/inner.txt").await);
    let sibling = f
        .store
        .get(f.owner, &p("photosX1/x.txt"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sibling.id, id);
    assert!(f.marker(id).await.is_some());
}

/// `Docs` and `docs` are different entries; SQLite's `LIKE` would have matched both.
#[tokio::test]
async fn names_differing_only_in_case_are_distinct() {
    let f = fixture().await;
    f.mkdir("Docs").await;
    f.write("Docs/inner.txt", 1).await;
    f.mkdir("docs").await;
    f.write("docs/x.txt", 1).await;
    let id = f.tag("docs/x.txt").await;
    assert_ne!(
        f.store.get(f.owner, &p("Docs")).await.unwrap().unwrap().id,
        f.store.get(f.owner, &p("docs")).await.unwrap().unwrap().id
    );

    f.store.record_delete(f.owner, &p("Docs")).await.unwrap();
    assert!(f.exists("docs/x.txt").await);
    assert!(f.marker(id).await.is_some());

    f.mkdir("DOCS").await;
    f.store
        .record_move(f.owner, &p("docs"), &p("Moved"), dir_stat())
        .await
        .unwrap();
    assert!(f.exists("DOCS").await, "case variant untouched by the move");
    assert!(f.exists("Moved/x.txt").await);
}

#[tokio::test]
async fn dead_props_follow_moves_and_copies_and_die_with_deletes() {
    let f = fixture().await;
    f.mkdir("dir").await;
    f.write("dir/file.txt", 1).await;
    let original = f.tag("dir/file.txt").await;
    let row = f
        .store
        .get(f.owner, &p("dir/file.txt"))
        .await
        .unwrap()
        .unwrap();
    f.store.set_favorite(row.id, true).await.unwrap();

    let copied = f
        .store
        .record_copy(
            f.owner,
            &p("dir"),
            &p("copied"),
            &[(RelPath::root(), dir_stat()), (p("file.txt"), file_stat(1))],
        )
        .await
        .unwrap();
    let copied_file = f
        .store
        .get(f.owner, &p("copied/file.txt"))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(copied.id, original);
    assert!(
        f.marker(copied_file.id).await.is_some(),
        "copied dead property"
    );
    assert!(!copied_file.favorite, "favorites are not copied");

    f.store
        .record_move(f.owner, &p("dir"), &p("moved"), dir_stat())
        .await
        .unwrap();
    let moved = f
        .store
        .get(f.owner, &p("moved/file.txt"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(moved.id, original);
    assert!(moved.favorite, "favorites move along");
    assert!(f.marker(original).await.is_some());

    f.store
        .record_delete(f.owner, &p("moved/file.txt"))
        .await
        .unwrap();
    assert!(f.marker(original).await.is_none());
    let reborn = f.write("moved/file.txt", 1).await;
    assert!(
        f.marker(reborn).await.is_none(),
        "delete and re-create starts clean"
    );
}

#[tokio::test]
async fn creation_times_survive_writes_and_moves_and_are_copied() {
    let f = fixture().await;
    let id = f.write("a.txt", 1).await;
    let row = |path: &'static str| {
        let store = f.store.clone();
        let owner = f.owner;
        async move { store.get(owner, &p(path)).await.unwrap().unwrap() }
    };
    assert_eq!(
        row("a.txt").await.creation_time,
        0,
        "unknown until reported"
    );
    let etag = f.etag("a.txt").await;
    f.store.set_creation_time(id, 1_600_000_000).await.unwrap();
    assert_eq!(row("a.txt").await.creation_time, 1_600_000_000);
    assert_eq!(f.etag("a.txt").await, etag, "not content");

    f.write("a.txt", 2).await;
    assert_eq!(row("a.txt").await.creation_time, 1_600_000_000, "overwrite");
    f.store
        .record_move(f.owner, &p("a.txt"), &p("b.txt"), file_stat(2))
        .await
        .unwrap();
    assert_eq!(row("b.txt").await.creation_time, 1_600_000_000, "move");
    let copy = f
        .store
        .record_copy(
            f.owner,
            &p("b.txt"),
            &p("c.txt"),
            &[(RelPath::root(), file_stat(2))],
        )
        .await
        .unwrap();
    assert_eq!(copy.creation_time, 1_600_000_000, "copy");
    assert_eq!(row("c.txt").await.creation_time, 1_600_000_000);
}

#[tokio::test]
async fn dead_props_can_be_set_replaced_and_removed() {
    let f = fixture().await;
    let id = f.write("props.txt", 1).await;
    let remove = |name: &str| PropChange::Remove("urn:test".into(), name.into());
    f.store
        .patch_dead_props(
            id,
            &[
                PropChange::Set(dead("color", "blue")),
                PropChange::Set(dead("size", "large")),
            ],
        )
        .await
        .unwrap();
    f.store
        .patch_dead_props(id, &[PropChange::Set(dead("color", "red")), remove("size")])
        .await
        .unwrap();
    assert_eq!(
        f.store.dead_props(id).await.unwrap(),
        [dead("color", "red")]
    );

    // Changes apply in request order.
    f.store
        .patch_dead_props(
            id,
            &[remove("shape"), PropChange::Set(dead("shape", "round"))],
        )
        .await
        .unwrap();
    f.store
        .patch_dead_props(id, &[PropChange::Set(dead("color", "x")), remove("color")])
        .await
        .unwrap();
    assert_eq!(
        f.store.dead_props(id).await.unwrap(),
        [dead("shape", "round")]
    );
}

#[tokio::test]
async fn moves_replace_the_destination() {
    let f = fixture().await;
    f.write("source.txt", 3).await;
    let target = f.write("target.txt", 10).await;
    f.tag("target.txt").await;
    assert_eq!(f.size("").await, 13);

    let moved = f
        .store
        .record_move(f.owner, &p("source.txt"), &p("target.txt"), file_stat(3))
        .await
        .unwrap();
    assert_ne!(moved.id, target);
    assert!(
        f.marker(target).await.is_none(),
        "replaced entry's metadata is gone"
    );
    assert_eq!(f.size("").await, 3);
}

#[tokio::test]
async fn adoption_creates_rows_without_signalling_a_change() {
    let f = fixture().await;
    let root_etag = f.etag("").await;
    let rows = f
        .store
        .adopt(
            f.owner,
            &[(p("found.txt"), file_stat(4)), (p("found-dir"), dir_stat())],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0].etag,
        gono_server_core::meta::derived_file_etag(rows[0].id, 1_000, 4)
    );
    assert_eq!(f.etag("").await, root_etag);
    let again = f
        .store
        .adopt(f.owner, &[(p("found.txt"), file_stat(9))])
        .await
        .unwrap();
    assert_eq!(again[0], rows[0], "existing rows are kept as they are");
    assert!(f.changes().await.is_empty());

    let many = f
        .store
        .get_many(f.owner, &[p("found.txt"), p("found-dir"), p("missing")])
        .await
        .unwrap();
    assert_eq!(many.len(), 2);
}

#[tokio::test]
async fn changes_are_logged_in_the_same_transaction() {
    let f = fixture().await;
    f.mkdir("d").await;
    f.write("d/a.txt", 1).await;
    f.write("d/a.txt", 2).await;
    f.store
        .record_move(f.owner, &p("d/a.txt"), &p("d/b.txt"), file_stat(2))
        .await
        .unwrap();
    f.store.record_delete(f.owner, &p("d")).await.unwrap();
    let ops = |op: &str, path: &str, old: Option<&str>| {
        (op.to_owned(), path.to_owned(), old.map(str::to_owned))
    };
    assert_eq!(
        f.changes().await,
        [
            ops("create", "d", None),
            ops("create", "d/a.txt", None),
            ops("modify", "d/a.txt", None),
            ops("move", "d/b.txt", Some("d/a.txt")),
            ops("delete", "d", None),
        ]
    );
    assert!(f.store.subtree(f.owner, &p("d")).await.unwrap().is_empty());
}

#[tokio::test]
async fn favorites_are_listed_by_subtree() {
    let f = fixture().await;
    f.mkdir("a").await;
    f.mkdir("a/b").await;
    f.mkdir("a_").await;
    for path in ["a/x.txt", "a/b/y.txt", "a_/z.txt", "top.txt"] {
        f.write(path, 1).await;
    }
    for path in ["a", "a/b/y.txt", "a_/z.txt", "top.txt"] {
        let id = f.store.get(f.owner, &p(path)).await.unwrap().unwrap().id;
        f.store.set_favorite(id, true).await.unwrap();
    }
    let paths = |rows: Vec<gono_server_core::meta::FileRow>| -> Vec<String> {
        rows.into_iter()
            .map(|row| row.rel_path.as_str().to_owned())
            .collect()
    };

    let below_a = f.store.favorites(f.owner, &p("a"), false).await.unwrap();
    assert_eq!(paths(below_a), ["a/b/y.txt"], "no wildcard sibling a_");
    let with_a = f.store.favorites(f.owner, &p("a"), true).await.unwrap();
    assert_eq!(paths(with_a), ["a", "a/b/y.txt"]);
    let everything = f
        .store
        .favorites(f.owner, &RelPath::root(), false)
        .await
        .unwrap();
    assert_eq!(paths(everything), ["a", "a/b/y.txt", "a_/z.txt", "top.txt"]);

    let root = f
        .store
        .get(f.owner, &RelPath::root())
        .await
        .unwrap()
        .unwrap();
    f.store.set_favorite(root.id, true).await.unwrap();
    let root_only =
        |rows: Vec<gono_server_core::meta::FileRow>| rows.iter().any(|r| r.rel_path.is_root());
    assert!(!root_only(
        f.store
            .favorites(f.owner, &RelPath::root(), false)
            .await
            .unwrap()
    ));
    assert!(root_only(
        f.store
            .favorites(f.owner, &RelPath::root(), true)
            .await
            .unwrap()
    ));
}

/// Records the published events.
#[derive(Debug, Default)]
struct Recorder(std::sync::Mutex<Vec<gono_server_core::meta::ChangeEvent>>);

impl gono_server_core::meta::ChangeSink for Recorder {
    fn publish(&self, event: &gono_server_core::meta::ChangeEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

#[tokio::test]
async fn every_logged_change_is_published_after_the_commit() {
    use gono_server_core::meta::ChangeOperation;

    let fixture = fixture().await;
    let recorder = std::sync::Arc::new(Recorder::default());
    let store = fixture.store.clone().with_sink(recorder.clone());
    let owner = fixture.owner;
    let before = store.latest_change_id().await.unwrap();

    let dir = store.record_mkdir(owner, &p("d"), 1).await.unwrap();
    let file = store
        .record_write(owner, &p("d/f.txt"), file_stat(3))
        .await
        .unwrap();
    store
        .record_write(owner, &p("d/f.txt"), file_stat(4))
        .await
        .unwrap();
    store
        .record_copy(owner, &p("d"), &p("e"), &[(RelPath::root(), dir_stat())])
        .await
        .unwrap();
    store
        .record_move(owner, &p("e"), &p("g"), dir_stat())
        .await
        .unwrap();
    store.record_delete(owner, &p("d")).await.unwrap();
    // Not content changes: nothing is published.
    store.set_favorite(file.id, true).await.unwrap();

    let published = recorder.0.lock().unwrap().clone();
    let summary: Vec<(ChangeOperation, &str, Option<&str>)> = published
        .iter()
        .map(|event| {
            (
                event.operation,
                event.rel_path.as_str(),
                event.old_rel_path.as_ref().map(RelPath::as_str),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (ChangeOperation::Create, "d", None),
            (ChangeOperation::Create, "d/f.txt", None),
            (ChangeOperation::Modify, "d/f.txt", None),
            (ChangeOperation::Create, "e", None),
            (ChangeOperation::Move, "g", Some("e")),
            (ChangeOperation::Delete, "d", None),
        ]
    );
    // The delete carries the id the directory had: its row is gone by now.
    assert_eq!(published[5].file_id, dir.id);
    assert!(store.get(owner, &p("d")).await.unwrap().is_none());
    assert!(published.iter().all(|event| event.owner_id == owner));

    // The change log holds the same events, in the same order, with the same ids.
    let logged = store.changes_since(before, 100).await.unwrap();
    assert_eq!(logged, published);
    assert_eq!(
        store.latest_change_id().await.unwrap(),
        published.last().unwrap().id
    );
    assert_eq!(
        store.changes_since(before, 2).await.unwrap(),
        published[..2]
    );
}

fn entries(list: &[(&str, Option<u64>)]) -> Vec<(RelPath, DiskStat)> {
    list.iter()
        .map(|(path, size)| {
            let stat = match size {
                Some(size) => file_stat(*size),
                None => dir_stat(),
            };
            (p(path), stat)
        })
        .collect()
}

#[tokio::test]
async fn reconcile_adds_removes_and_updates_what_changed_on_disk() {
    use gono_server_core::meta::ChangeOperation;

    let fixture = fixture().await;
    let recorder = std::sync::Arc::new(Recorder::default());
    let store = fixture.store.clone().with_sink(recorder.clone());
    let owner = fixture.owner;
    store.record_mkdir(owner, &p("docs"), 1).await.unwrap();
    let kept = store
        .record_write(owner, &p("docs/kept.txt"), file_stat(10))
        .await
        .unwrap();
    let changed = store
        .record_write(owner, &p("docs/changed.txt"), file_stat(20))
        .await
        .unwrap();
    store.record_mkdir(owner, &p("old"), 1).await.unwrap();
    store
        .record_write(owner, &p("old/gone.txt"), file_stat(5))
        .await
        .unwrap();
    let root_before = store.get(owner, &RelPath::root()).await.unwrap().unwrap();
    assert_eq!(root_before.size, 35);
    recorder.0.lock().unwrap().clear();

    // On disk: `old` is gone, `changed.txt` grew, `new/a/b.txt` appeared.
    let disk = entries(&[
        ("", None),
        ("docs", None),
        ("docs/changed.txt", Some(25)),
        ("docs/kept.txt", Some(10)),
        ("new", None),
        ("new/a", None),
        ("new/a/b.txt", Some(7)),
    ]);
    let dry = store
        .reconcile(owner, &RelPath::root(), &[], &disk, true)
        .await
        .unwrap();
    assert_eq!(dry.added, [p("new")]);
    assert!(
        recorder.0.lock().unwrap().is_empty(),
        "a dry run publishes nothing"
    );
    assert!(
        store.get(owner, &p("old")).await.unwrap().is_some(),
        "and changes nothing"
    );

    let report = store
        .reconcile(owner, &RelPath::root(), &[], &disk, false)
        .await
        .unwrap();
    assert_eq!(report, dry, "the dry run predicts the real run");
    assert_eq!(report.added, [p("new")]);
    assert_eq!(report.added_rows, 3);
    assert_eq!(report.removed, [p("old")]);
    assert_eq!(report.removed_rows, 2);
    assert_eq!(report.modified, [p("docs/changed.txt")]);

    // Rows, sizes and ETags.
    assert!(
        store
            .get(owner, &p("old/gone.txt"))
            .await
            .unwrap()
            .is_none()
    );
    let file = store
        .get(owner, &p("docs/changed.txt"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(file.id, changed.id, "the file id is kept");
    assert_eq!(
        file.etag,
        gono_server_core::meta::derived_file_etag(file.id, 1_000, 25)
    );
    let unchanged = store
        .get(owner, &p("docs/kept.txt"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.etag, kept.etag);
    let root = store.get(owner, &RelPath::root()).await.unwrap().unwrap();
    assert_eq!(root.size, 42);
    assert_ne!(root.etag, root_before.etag);
    assert_eq!(
        store.get(owner, &p("new/a")).await.unwrap().unwrap().size,
        7
    );

    // The change log names every top-most change, in order.
    let published: Vec<(ChangeOperation, String)> = recorder
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|event| (event.operation, event.rel_path.as_str().to_owned()))
        .collect();
    assert_eq!(
        published,
        [
            (ChangeOperation::Delete, "old".to_owned()),
            (ChangeOperation::Create, "new".to_owned()),
            (ChangeOperation::Modify, "docs/changed.txt".to_owned()),
        ]
    );

    // A second run finds nothing to do.
    let again = store
        .reconcile(owner, &RelPath::root(), &[], &disk, false)
        .await
        .unwrap();
    assert!(again.is_empty(), "{again:?}");
}

#[tokio::test]
async fn reconcile_of_a_subtree_corrects_sizes_and_leaves_the_rest_alone() {
    let fixture = fixture().await;
    let store = &fixture.store;
    let owner = fixture.owner;
    store.record_mkdir(owner, &p("a"), 1).await.unwrap();
    store.record_mkdir(owner, &p("a/b"), 1).await.unwrap();
    store
        .record_write(owner, &p("a/b/f.txt"), file_stat(10))
        .await
        .unwrap();
    store
        .record_write(owner, &p("other.txt"), file_stat(100))
        .await
        .unwrap();
    let a_before = store.get(owner, &p("a")).await.unwrap().unwrap();

    // `a/b` lost its file and got a bigger one; the rest of the tree is not looked at.
    let ancestors = entries(&[("", None), ("a", None)]);
    let disk = entries(&[("a/b", None), ("a/b/g.txt", Some(30))]);
    let report = store
        .reconcile(owner, &p("a/b"), &ancestors, &disk, false)
        .await
        .unwrap();
    assert_eq!(report.added, [p("a/b/g.txt")]);
    assert_eq!(report.removed, [p("a/b/f.txt")]);
    assert!(store.get(owner, &p("other.txt")).await.unwrap().is_some());
    assert_eq!(store.get(owner, &p("a/b")).await.unwrap().unwrap().size, 30);
    let a = store.get(owner, &p("a")).await.unwrap().unwrap();
    assert_eq!(a.size, 30);
    assert_ne!(a.etag, a_before.etag);
    assert_eq!(
        store
            .get(owner, &RelPath::root())
            .await
            .unwrap()
            .unwrap()
            .size,
        130
    );

    // A scope that disappeared takes its rows along; its ancestors shrink.
    let report = store
        .reconcile(owner, &p("a/b"), &ancestors, &[], false)
        .await
        .unwrap();
    assert_eq!(report.removed, [p("a/b")]);
    assert_eq!(report.removed_rows, 2);
    assert_eq!(store.get(owner, &p("a")).await.unwrap().unwrap().size, 0);
    assert_eq!(
        store
            .get(owner, &RelPath::root())
            .await
            .unwrap()
            .unwrap()
            .size,
        100
    );
}

#[tokio::test]
async fn reconcile_fixes_drifted_directory_sizes() {
    let fixture = fixture().await;
    let store = &fixture.store;
    let owner = fixture.owner;
    store.record_mkdir(owner, &p("d"), 1).await.unwrap();
    store
        .record_write(owner, &p("d/f"), file_stat(8))
        .await
        .unwrap();
    sqlx::query("UPDATE files SET size = 999 WHERE rel_path = 'd'")
        .execute(store.pool())
        .await
        .unwrap();
    let disk = entries(&[("", None), ("d", None), ("d/f", Some(8))]);
    let report = store
        .reconcile(owner, &RelPath::root(), &[], &disk, false)
        .await
        .unwrap();
    assert_eq!(report.resized, 1);
    assert!(report.added.is_empty() && report.removed.is_empty());
    assert_eq!(store.get(owner, &p("d")).await.unwrap().unwrap().size, 8);
}
