//! Rebuilds the crate whenever a migration changes. `sqlx::migrate!` embeds the files at compile
//! time, and Cargo does not track them on its own.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
