//! The `scan` binary against a fake home. It must not read the real one.

use std::fs::{self, File};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

fn set_tree_mtime(root: &Path, mtime: SystemTime) {
    let meta = fs::symlink_metadata(root).expect("fixture path can be stated");
    if meta.file_type().is_symlink() {
        return;
    }
    File::open(root)
        .expect("fixture path can be opened")
        .set_modified(mtime)
        .expect("fixture mtime can be set");
    if meta.is_dir() {
        for entry in fs::read_dir(root).expect("fixture directory can be listed") {
            let entry = entry.expect("fixture directory entry can be read");
            set_tree_mtime(&entry.path(), mtime);
        }
    }
}

#[test]
fn scan_on_a_fake_home_reports_the_cache_and_does_not_delete_it() {
    let root = std::env::temp_dir().join(format!("disk-health-cli-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let home = root.join("home");
    let cache = home.join(".cargo/registry");
    let projects = root.join("projects");
    fs::create_dir_all(&cache).unwrap();
    fs::create_dir_all(&projects).unwrap();
    let blob = cache.join("crate.tar");
    fs::write(&blob, b"crate-bytes").unwrap();
    let old = SystemTime::now() - Duration::from_hours(30 * 24);
    set_tree_mtime(&home, old);

    let binary = env!("CARGO_BIN_EXE_disk-health");
    let output = Command::new(binary)
        .args([
            "scan",
            "--home",
            home.to_str().unwrap(),
            "--root",
            projects.to_str().unwrap(),
            "--format",
            "text",
            "--fail-over",
            "1GiB",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "status {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(stdout.contains("cargo-registry"), "{stdout}");
    assert!(stdout.contains("staged"), "{stdout}");
    assert_eq!(fs::read(&blob).unwrap(), b"crate-bytes");

    let _ = fs::remove_dir_all(&root);
}
