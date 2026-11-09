//! MetaStore against a real SQLite database: file ids, ETag and size propagation, dead
//! properties, and subtree operations on names that `LIKE` would get wrong.

use gono_core::{
    RelPath, Username,
    config::DbConfig,
    db::{self, OpenMode, Pool},
    meta::{DeadProp, DiskStat, MetaStore},
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
            .patch_dead_props(row.id, &[dead("marker", "keep-me")], &[])
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
async fn dead_props_can_be_set_replaced_and_removed() {
    let f = fixture().await;
    let id = f.write("props.txt", 1).await;
    f.store
        .patch_dead_props(id, &[dead("color", "blue"), dead("size", "large")], &[])
        .await
        .unwrap();
    f.store
        .patch_dead_props(
            id,
            &[dead("color", "red")],
            &[("urn:test".into(), "size".into())],
        )
        .await
        .unwrap();
    let props = f.store.dead_props(id).await.unwrap();
    assert_eq!(props, [dead("color", "red")]);
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
        gono_core::meta::derived_file_etag(rows[0].id, 1_000, 4)
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
