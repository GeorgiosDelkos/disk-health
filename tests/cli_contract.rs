//! CLI contract for plan files, apply, and usage.
//!
//! Every test passes `--home` and, for scans, `--root`. The defaults would
//! walk this machine, including `/Volumes/Source`.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use disk_health::plan::Plan;

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("disk-health-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("scratch directory can be created");
        Self { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_disk-health"))
        .args(args)
        .output()
        .expect("disk-health binary starts")
}

fn explain(output: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn own(text: impl AsRef<str>) -> String {
    text.as_ref().to_owned()
}

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

fn read_plan(path: &Path) -> Plan {
    let text = fs::read_to_string(path).expect("plan file can be read");
    assert!(
        !text.contains("\"kind\""),
        "plan file must not be the scan report:\n{text}"
    );
    Plan::parse(&text).expect("plan file parses")
}

#[test]
fn plan_file_is_not_the_scan_report_and_empty_apply_exits_0() {
    let scratch = Scratch::new("empty-plan");
    let home = scratch.path.join("home");
    let projects = scratch.path.join("projects");
    let plan_path = scratch.path.join("plan.json");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&projects).unwrap();

    let output = run(&[
        own("scan"),
        own("--home"),
        home.display().to_string(),
        own("--root"),
        projects.display().to_string(),
        own("--format"),
        own("json"),
        own("--plan"),
        plan_path.display().to_string(),
    ]);
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(output.status.success(), "{}", explain(&output));
    assert!(stdout.contains("\"kind\": \"scan\""), "{stdout}");

    let plan = read_plan(&plan_path);
    assert_eq!(plan.schema, 1);
    assert!(plan.entries.is_empty(), "{plan:?}");

    let applied = run(&[
        own("apply"),
        own("--home"),
        home.display().to_string(),
        own("--plan"),
        plan_path.display().to_string(),
        own("--confirm"),
        plan.plan_id.clone(),
    ]);
    assert!(applied.status.success(), "{}", explain(&applied));
    assert_eq!(applied.status.code(), Some(0));
}

#[test]
fn missing_plan_parent_is_not_created() {
    let scratch = Scratch::new("missing-plan");
    let home = scratch.path.join("home");
    let projects = scratch.path.join("projects");
    let parent = scratch.path.join("no-such-dir");
    let plan_path = parent.join("plan.json");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&projects).unwrap();

    let output = run(&[
        own("scan"),
        own("--home"),
        home.display().to_string(),
        own("--root"),
        projects.display().to_string(),
        own("--plan"),
        plan_path.display().to_string(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", explain(&output));
    assert!(!parent.exists());
    assert!(!plan_path.exists());
}

#[test]
fn wrong_confirm_moves_nothing() {
    let scratch = Scratch::new("wrong-confirm");
    let home = scratch.path.join("home");
    let projects = scratch.path.join("projects");
    let cache = home.join(".cargo/registry");
    let blob = cache.join("crate.tar");
    let plan_path = scratch.path.join("plan.json");
    fs::create_dir_all(&cache).unwrap();
    fs::create_dir_all(&projects).unwrap();
    fs::write(&blob, b"crate-bytes").unwrap();
    let old = SystemTime::now() - Duration::from_hours(30 * 24);
    set_tree_mtime(&home, old);

    let scanned = run(&[
        own("scan"),
        own("--home"),
        home.display().to_string(),
        own("--root"),
        projects.display().to_string(),
        own("--format"),
        own("json"),
        own("--plan"),
        plan_path.display().to_string(),
    ]);
    let stdout = String::from_utf8(scanned.stdout.clone()).unwrap();
    assert!(scanned.status.success(), "{}", explain(&scanned));
    assert!(stdout.contains("\"staged\": true"), "{stdout}");

    let plan = read_plan(&plan_path);
    assert!(plan.entries.iter().any(|entry| entry.staged), "{plan:?}");
    assert_ne!(plan.plan_id, "not-the-plan");

    let applied = run(&[
        own("apply"),
        own("--home"),
        home.display().to_string(),
        own("--plan"),
        plan_path.display().to_string(),
        own("--confirm"),
        own("not-the-plan"),
    ]);
    let stderr = String::from_utf8(applied.stderr.clone()).unwrap();
    assert_eq!(applied.status.code(), Some(1), "{}", explain(&applied));
    assert!(stderr.contains("does not match"), "{stderr}");
    assert_eq!(fs::read(&blob).unwrap(), b"crate-bytes");
}

#[test]
fn usage_of_a_temp_volume_has_no_staged_key() {
    let scratch = Scratch::new("usage");
    let home = scratch.path.join("home");
    let volume = scratch.path.join("volume");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&volume).unwrap();
    fs::write(volume.join("blob.bin"), b"abcd").unwrap();

    let output = run(&[
        own("usage"),
        own("--home"),
        home.display().to_string(),
        own("--volume"),
        volume.display().to_string(),
        own("--format"),
        own("json"),
    ]);
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(output.status.success(), "{}", explain(&output));
    assert!(stdout.contains("\"kind\": \"usage\""), "{stdout}");
    assert!(stdout.contains("blob.bin"), "{stdout}");
    assert!(!stdout.contains("\"staged\""), "{stdout}");
    assert!(!stdout.contains("\"tier\""), "{stdout}");
}

#[test]
fn usage_of_system_is_refused() {
    let scratch = Scratch::new("usage-system");
    let home = scratch.path.join("home");
    fs::create_dir_all(&home).unwrap();

    let output = run(&[
        own("usage"),
        own("--home"),
        home.display().to_string(),
        own("--volume"),
        own("/System"),
    ]);
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", explain(&output));
    assert!(stderr.contains("refuses"), "{stderr}");
    assert!(stderr.contains("/System"), "{stderr}");
}
