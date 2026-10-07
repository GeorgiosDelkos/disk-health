//! Safety properties of the read-only scan.
//!
//! These tests fail if a symlink is followed, a marker is ignored, or a
//! denylisted prefix becomes a candidate. None of them touch the real home
//! directory. `MemFs` is the double; `RealFs` covers `lstat` and `flock`.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use disk_health::config::deny_prefixes;
use disk_health::git::{GitTree, MapGit};
use disk_health::rules::{self, SafeAnchor, SafeRule, Skip, Tier};
use disk_health::scan::{Report, ScanOptions, scan};
use disk_health::walk::{Kind, MemFs, RealFs, SF_DATALESS};

fn now() -> SystemTime {
    // 1_800_000_000 is a fixed unix timestamp, not a count of hours.
    #[allow(clippy::duration_suboptimal_units, reason = "fixed unix timestamp")]
    let offset = Duration::from_secs(1_800_000_000);
    SystemTime::UNIX_EPOCH + offset
}

fn old() -> SystemTime {
    now() - Duration::from_hours(30 * 24)
}

#[allow(
    clippy::too_many_arguments,
    reason = "test helper forwards the scan inputs without packing them twice"
)]
fn run(
    fs: &MemFs,
    git: &MapGit,
    home: &Path,
    roots: &[PathBuf],
    safe_rules: &[SafeRule],
    project_rules: &[disk_health::rules::ProjectRule],
    deny: &[PathBuf],
) -> Report {
    scan(&ScanOptions {
        home,
        roots,
        safe_rules,
        project_rules,
        deny,
        now: now(),
        git,
        fs,
        progress: None,
        on_finding: None,
    })
    .expect("a scan worker can be spawned")
}

fn fixture_rule(relative: &'static str) -> SafeRule {
    SafeRule {
        id: "fixture",
        anchor: SafeAnchor::Directory(relative),
        min_age: rules::HOT_WINDOW,
        regenerate: Some("refill"),
        rationale: "fixture",
        locks: &[],
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "disk-health-{label}-{}-{}",
            std::process::id(),
            label.len()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp fixture directory can be created");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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

#[test]
fn symlink_node_modules_is_not_a_candidate() {
    let temp = TempDir::new("symlink");
    let home = temp.path().join("home");
    let project = home.join("app");
    let precious = temp.path().join("precious");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&precious).unwrap();
    fs::write(precious.join("secret.txt"), b"keep").unwrap();
    fs::write(project.join("package.json"), b"{}").unwrap();
    fs::write(project.join("package-lock.json"), b"{}").unwrap();
    std::os::unix::fs::symlink(&precious, project.join("node_modules")).unwrap();
    set_tree_mtime(temp.path(), old());

    let git = MapGit::default();
    let fs = RealFs;
    let roots = [home.clone()];
    let deny = deny_prefixes(&home, &[]);
    let safe = rules::builtin_safe();
    let project_rules = rules::builtin_project();
    let report = scan(&ScanOptions {
        home: &home,
        roots: &roots,
        safe_rules: &safe,
        project_rules: &project_rules,
        deny: &deny,
        now: now(),
        git: &git,
        fs: &fs,
        progress: None,
        on_finding: None,
    })
    .expect("a scan worker can be spawned");

    assert!(
        report
            .findings
            .iter()
            .all(|finding| !finding.path.starts_with(&precious)),
        "followed the symlink into precious: {:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.path.file_name() != Some(OsStr::new("node_modules"))),
        "symlink node_modules became a candidate: {:?}",
        report.findings
    );
    assert_eq!(fs::read(precious.join("secret.txt")).unwrap(), b"keep");
}

#[test]
fn target_without_a_regular_cargo_toml_is_not_a_candidate() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    fs.dir("/h/lonely", 1, old());
    fs.dir("/h/lonely/target", 1, old());
    fs.file("/h/lonely/target/CACHEDIR.TAG", 1, 43, old());
    fs.file("/h/lonely/target/a.o", 1, 8, old());
    fs.dir("/h/linked", 1, old());
    fs.symlink("/h/linked/Cargo.toml", old());
    fs.dir("/h/linked/target", 1, old());
    fs.file("/h/linked/target/CACHEDIR.TAG", 1, 43, old());
    fs.file("/h/linked/target/a.o", 1, 8, old());

    let git = MapGit::default();
    let home = PathBuf::from("/h");
    let roots = [home.clone()];
    let report = run(
        &fs,
        &git,
        &home,
        &roots,
        &[],
        &rules::builtin_project(),
        &deny_prefixes(&home, &[]),
    );
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn node_modules_without_a_lockfile_is_not_a_candidate() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    fs.dir("/h/app", 1, old());
    fs.file("/h/app/package.json", 1, 2, old());
    fs.dir("/h/app/node_modules", 1, old());
    fs.file("/h/app/node_modules/pkg.js", 1, 4, old());

    let git = MapGit::default();
    let home = PathBuf::from("/h");
    let roots = [home.clone()];
    let report = run(
        &fs,
        &git,
        &home,
        &roots,
        &[],
        &rules::builtin_project(),
        &deny_prefixes(&home, &[]),
    );
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn denylist_beats_a_rule_that_names_the_path() {
    let fs = MemFs::new();
    fs.dir("/", 1, old());
    fs.dir("/Library", 1, old());
    fs.dir("/Library/Keychains", 1, old());
    fs.dir("/Library/Keychains/secret", 1, old());
    fs.file("/Library/Keychains/secret/login.keychain-db", 1, 32, old());
    fs.dir("/System", 1, old());
    fs.dir("/System/cache", 1, old());
    fs.file("/System/cache/data", 1, 32, old());

    let rules = [
        fixture_rule("Library/Keychains/secret"),
        SafeRule {
            id: "system",
            anchor: SafeAnchor::Directory("System/cache"),
            min_age: rules::HOT_WINDOW,
            regenerate: Some("no"),
            rationale: "must not match",
            locks: &[],
        },
    ];
    // The system rule is resolved against home `/`, so it lands on `/System/cache`.
    let git = MapGit::default();
    let system_home = PathBuf::from("/");
    let deny = deny_prefixes(&system_home, &[]);
    let report = run(&fs, &git, &system_home, &[], &rules, &[], &deny);
    assert!(
        report.findings.is_empty(),
        "denylist leaked: {:?}",
        report.findings
    );
}

#[test]
fn different_device_is_not_entered() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    fs.dir("/h/proj", 1, old());
    fs.dir("/h/proj/other", 2, old());
    fs.file("/h/proj/other/Cargo.toml", 2, 2, old());
    fs.dir("/h/proj/other/target", 2, old());
    fs.file("/h/proj/other/target/CACHEDIR.TAG", 2, 43, old());
    fs.file("/h/proj/other/target/a.o", 2, 1_000, old());

    let git = MapGit::default();
    let home = PathBuf::from("/h");
    let roots = [home.join("proj")];
    let report = run(
        &fs,
        &git,
        &home,
        &roots,
        &[],
        &rules::builtin_project(),
        &deny_prefixes(&home, &[]),
    );
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn mount_inside_a_cache_is_not_staged_and_not_counted() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    fs.dir("/h/cache", 1, old());
    fs.file("/h/cache/keep", 1, 10, old());
    fs.dir("/h/cache/mnt", 2, old());
    fs.file("/h/cache/mnt/big", 2, 1_000_000, old());

    let git = MapGit::default();
    let home = PathBuf::from("/h");
    let rules = [fixture_rule("cache")];
    let report = run(
        &fs,
        &git,
        &home,
        &[],
        &rules,
        &[],
        &deny_prefixes(&home, &[]),
    );
    assert_eq!(report.findings.len(), 1);
    let finding = &report.findings[0];
    assert!(!finding.staged());
    assert_eq!(finding.skip, Some(Skip::CrossedDevice));
    assert_eq!(finding.apparent_bytes, 10);
}

#[test]
fn dataless_directory_is_not_descended() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    fs.dir("/h/proj", 1, old());
    fs.dir("/h/proj/cloud", 1, old());
    fs.set_flags(Path::new("/h/proj/cloud"), SF_DATALESS);
    fs.file("/h/proj/cloud/Cargo.toml", 1, 2, old());
    fs.dir("/h/proj/cloud/target", 1, old());
    fs.file("/h/proj/cloud/target/CACHEDIR.TAG", 1, 43, old());
    fs.file("/h/proj/cloud/target/a.o", 1, 8, old());

    let git = MapGit::default();
    let home = PathBuf::from("/h");
    let roots = [home.join("proj")];
    let report = run(
        &fs,
        &git,
        &home,
        &roots,
        &[],
        &rules::builtin_project(),
        &deny_prefixes(&home, &[]),
    );
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn locked_directory_is_reported_and_not_staged() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    fs.dir("/h/cache", 1, old());
    fs.file("/h/cache/blob", 1, 4, old());
    fs.lock_path(Path::new("/h/cache"));

    let git = MapGit::default();
    let home = PathBuf::from("/h");
    let rules = [fixture_rule("cache")];
    let report = run(
        &fs,
        &git,
        &home,
        &[],
        &rules,
        &[],
        &deny_prefixes(&home, &[]),
    );
    assert_eq!(report.findings.len(), 1);
    assert!(!report.findings[0].staged());
    assert_eq!(report.findings[0].skip, Some(Skip::Locked));
}

#[test]
fn real_flock_skips_the_directory() {
    let temp = TempDir::new("flock");
    let home = temp.path().join("home");
    let cache = home.join("cache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("blob"), b"data").unwrap();
    set_tree_mtime(&home, old());

    let mut child = Command::new("perl")
        .arg("-e")
        .arg(
            "use Fcntl qw(:flock); open my $fh, '<', $ARGV[0] or die $!; \
             flock($fh, LOCK_EX | LOCK_NB) or die $!; $| = 1; print \"locked\\n\"; sleep 60;",
        )
        .arg(&cache)
        .stdout(Stdio::piped())
        .spawn()
        .expect("perl is on macOS");
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    std::io::BufRead::read_line(&mut stdout, &mut line).unwrap();
    assert_eq!(line, "locked\n", "perl did not take the lock");

    let git = MapGit::default();
    let fs = RealFs;
    let rules = [fixture_rule("cache")];
    let deny = deny_prefixes(&home, &[]);
    let report = scan(&ScanOptions {
        home: &home,
        roots: &[],
        safe_rules: &rules,
        project_rules: &[],
        deny: &deny,
        now: now(),
        git: &git,
        fs: &fs,
        progress: None,
        on_finding: None,
    })
    .expect("a scan worker can be spawned");

    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    assert!(!report.findings[0].staged());
    assert_eq!(report.findings[0].skip, Some(Skip::Locked));
}

#[test]
fn dirty_tree_is_not_staged_and_clean_tree_is() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    for name in ["dirty", "clean"] {
        let project = format!("/h/{name}");
        fs.dir(&project, 1, old());
        fs.file(format!("{project}/Cargo.toml"), 1, 2, old());
        cargo_target(&fs, &project);
    }
    let mut git = MapGit::default();
    git.by_path
        .insert(PathBuf::from("/h/dirty"), GitTree::Dirty);
    git.by_path
        .insert(PathBuf::from("/h/clean"), GitTree::Clean);

    let home = PathBuf::from("/h");
    let roots = [home.clone()];
    let report = run(
        &fs,
        &git,
        &home,
        &roots,
        &[],
        &rules::builtin_project(),
        &deny_prefixes(&home, &[]),
    );
    let dirty = report
        .findings
        .iter()
        .find(|finding| finding.path.ends_with("dirty/target"))
        .expect("dirty target is still reported");
    let clean = report
        .findings
        .iter()
        .find(|finding| finding.path.ends_with("clean/target"))
        .expect("clean target is reported");
    assert_eq!(dirty.skip, Some(Skip::Dirty));
    assert!(!dirty.staged());
    assert!(clean.staged(), "{:?}", clean.skip);
    assert_eq!(clean.tier, Tier::Caution);
}

/// A `target` directory cargo would recognize as its own, with one object file.
fn cargo_target(fs: &MemFs, project: &str) {
    fs.dir(format!("{project}/target"), 1, old());
    fs.file(format!("{project}/target/CACHEDIR.TAG"), 1, 43, old());
    fs.dir(format!("{project}/target/debug"), 1, old());
    fs.file(format!("{project}/target/debug/.cargo-lock"), 1, 0, old());
    fs.file(format!("{project}/target/debug/a.o"), 1, 8, old());
}

fn scan_projects(fs: &MemFs, git: &dyn disk_health::git::GitProbe) -> Report {
    let home = PathBuf::from("/h");
    let roots = [home.clone()];
    scan(&ScanOptions {
        home: &home,
        roots: &roots,
        safe_rules: &[],
        project_rules: &rules::builtin_project(),
        deny: &deny_prefixes(&home, &[]),
        now: now(),
        git,
        fs,
        progress: None,
        on_finding: None,
    })
    .expect("a scan worker can be spawned")
}

#[test]
fn directory_named_target_that_cargo_did_not_write_is_not_a_candidate() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    fs.dir("/h/crate", 1, old());
    fs.file("/h/crate/Cargo.toml", 1, 2, old());
    fs.dir("/h/crate/target", 1, old());
    fs.file("/h/crate/target/quarterly-targets.xlsx", 1, 900, old());

    let report = scan_projects(&fs, &MapGit::default());
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn cargo_build_lock_holds_the_target_at_either_depth() {
    for lock in [
        "/h/crate/target/debug/.cargo-lock",
        "/h/crate/target/aarch64-apple-darwin/release/.cargo-lock",
    ] {
        let fs = MemFs::new();
        fs.dir("/h", 1, old());
        fs.dir("/h/crate", 1, old());
        fs.file("/h/crate/Cargo.toml", 1, 2, old());
        cargo_target(&fs, "/h/crate");
        fs.dir("/h/crate/target/aarch64-apple-darwin", 1, old());
        fs.dir("/h/crate/target/aarch64-apple-darwin/release", 1, old());
        fs.file(
            "/h/crate/target/aarch64-apple-darwin/release/.cargo-lock",
            1,
            0,
            old(),
        );

        let free = scan_projects(&fs, &MapGit::default());
        assert!(free.findings[0].staged(), "{:?}", free.findings);

        // The directory is not locked. Only the file cargo holds is.
        fs.lock_path(Path::new(lock));
        let held = scan_projects(&fs, &MapGit::default());
        assert_eq!(held.findings[0].skip, Some(Skip::Locked), "{lock}");
    }
}

#[test]
fn cargo_home_lock_holds_the_registry() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    fs.dir("/h/.cargo", 1, old());
    fs.file("/h/.cargo/.package-cache", 1, 0, old());
    fs.dir("/h/.cargo/registry", 1, old());
    fs.file("/h/.cargo/registry/crate.tar", 1, 64, old());
    fs.lock_path(Path::new("/h/.cargo/.package-cache"));

    let home = PathBuf::from("/h");
    let report = run(
        &fs,
        &MapGit::default(),
        &home,
        &[],
        &rules::builtin_safe(),
        &[],
        &deny_prefixes(&home, &[]),
    );
    assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    assert_eq!(report.findings[0].skip, Some(Skip::Locked));
}

#[test]
fn mount_point_listed_as_a_plain_directory_is_not_entered() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    // Inside a candidate: the cache must not be staged or sized through it.
    fs.dir("/h/crate", 1, old());
    fs.file("/h/crate/Cargo.toml", 1, 2, old());
    cargo_target(&fs, "/h/crate");
    fs.dir("/h/crate/target/mnt", 1, old());
    fs.file("/h/crate/target/mnt/other-disk.img", 2, 1_000_000, old());
    fs.mount(Path::new("/h/crate/target/mnt"), 2);
    // An empty mount has no child to give the other device away.
    fs.dir("/h/idle", 1, old());
    fs.file("/h/idle/Cargo.toml", 1, 2, old());
    cargo_target(&fs, "/h/idle");
    fs.dir("/h/idle/target/mnt", 1, old());
    fs.mount(Path::new("/h/idle/target/mnt"), 2);
    // On the way to a candidate: the walk must not find a project behind it.
    fs.dir("/h/backup", 1, old());
    fs.file("/h/backup/Cargo.toml", 2, 2, old());
    cargo_target(&fs, "/h/backup");
    fs.mount(Path::new("/h/backup"), 2);

    let report = scan_projects(&fs, &MapGit::default());
    assert_eq!(report.findings.len(), 2, "{:?}", report.findings);
    for (finding, path) in report
        .findings
        .iter()
        .zip(["/h/crate/target", "/h/idle/target"])
    {
        assert_eq!(finding.path, Path::new(path));
        assert_eq!(finding.skip, Some(Skip::CrossedDevice), "{path}");
        assert_eq!(finding.apparent_bytes, 43 + 8, "{path}");
    }

    let tree = disk_health::usage::walk(&fs, Path::new("/h"), 4, None).unwrap();
    assert_eq!(tree.apparent_bytes, 2 * (2 + 43 + 8));
}

#[test]
fn another_disk_is_not_scanned() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    // A project root on a USB disk.
    fs.dir("/usb", 2, old());
    fs.dir("/usb/crate", 2, old());
    fs.file("/usb/crate/Cargo.toml", 2, 2, old());
    fs.dir("/usb/crate/target", 2, old());
    fs.file("/usb/crate/target/CACHEDIR.TAG", 2, 43, old());
    // A cache that was moved onto it.
    fs.dir("/h/cache", 2, old());
    fs.file("/h/cache/blob", 2, 4_000, old());

    let home = PathBuf::from("/h");
    let roots = [PathBuf::from("/usb")];
    let report = run(
        &fs,
        &MapGit::default(),
        &home,
        &roots,
        &[fixture_rule("cache")],
        &rules::builtin_project(),
        &deny_prefixes(&home, &[]),
    );
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.roots_denied, roots);
    assert_eq!(report.dirs_visited, 0);
}

/// Counts how often the scan asks about a project.
#[derive(Default)]
struct CountingGit(std::sync::atomic::AtomicUsize);

impl disk_health::git::GitProbe for CountingGit {
    fn status(&self, _project: &Path) -> GitTree {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        GitTree::Clean
    }
}

#[test]
fn git_is_asked_once_per_project_not_once_per_rule() {
    let fs = MemFs::new();
    fs.dir("/h", 1, old());
    fs.dir("/h/app", 1, old());
    fs.file("/h/app/package.json", 1, 2, old());
    fs.file("/h/app/package-lock.json", 1, 2, old());
    for child in ["node_modules", ".next", ".turbo"] {
        fs.dir(format!("/h/app/{child}"), 1, old());
        fs.file(format!("/h/app/{child}/blob"), 1, 4, old());
    }

    let git = CountingGit::default();
    let report = scan_projects(&fs, &git);
    assert_eq!(report.findings.len(), 3, "{:?}", report.findings);
    assert!(
        report
            .findings
            .iter()
            .all(disk_health::scan::Finding::staged)
    );
    // Two workers can race to the first answer, so the bound is not exactly 1.
    let asked = git.0.load(std::sync::atomic::Ordering::Relaxed);
    assert!((1..3).contains(&asked), "git status ran {asked} times");
}

#[test]
fn random_trees_never_stage_a_symlink_or_a_denied_path() {
    let mut rng = XorShift(0xD15C_5AFE);
    for iteration in 0..200 {
        let seed = rng.0;
        let fs = MemFs::new();
        fs.dir("/h", 1, old());
        fs.dir("/h/work", 1, old());
        fs.dir("/h/Library", 1, old());
        fs.dir("/h/Library/Keychains", 1, old());
        fs.dir("/h/Library/Keychains/secret", 1, old());
        fs.file("/h/Library/Keychains/secret/login", 1, 8, old());
        fs.dir("/System", 1, old());
        fs.dir("/System/evil", 1, old());
        fs.file("/System/evil/Cargo.toml", 1, 2, old());
        fs.dir("/System/evil/target", 1, old());
        fs.file("/System/evil/target/CACHEDIR.TAG", 1, 43, old());
        fs.file("/System/evil/target/a.o", 1, 8, old());

        let app = format!("/h/work/app{iteration}");
        fs.dir(&app, 1, old());
        fs.file(format!("{app}/package.json"), 1, 2, old());
        let precious = format!("/h/precious{iteration}");
        fs.dir(&precious, 1, old());
        fs.file(format!("{precious}/secret.txt"), 1, 8, old());

        let mode = rng.next() % 3;
        let modules = format!("{app}/node_modules");
        if mode == 0 {
            fs.symlink(&modules, old());
        } else {
            fs.dir(&modules, 1, old());
            fs.file(format!("{modules}/pkg.js"), 1, 4, old());
            if mode == 1 {
                fs.file(format!("{app}/package-lock.json"), 1, 2, old());
            }
        }

        let git = MapGit::default();
        let home = PathBuf::from("/h");
        let roots = [home.join("work"), PathBuf::from("/System")];
        let deny = deny_prefixes(&home, &[]);
        let safe = [fixture_rule("Library/Keychains/secret")];
        let report = run(
            &fs,
            &git,
            &home,
            &roots,
            &safe,
            &rules::builtin_project(),
            &deny,
        );

        for finding in &report.findings {
            assert_ne!(
                fs.kind(&finding.path),
                Some(Kind::Symlink),
                "seed {seed:#x} iteration {iteration} staged a symlink {}",
                finding.path.display()
            );
            assert!(
                !finding.path.starts_with("/System"),
                "seed {seed:#x} iteration {iteration} entered /System"
            );
            assert!(
                !finding.path.starts_with("/h/Library/Keychains"),
                "seed {seed:#x} iteration {iteration} entered the keychain"
            );
            if finding.path.ends_with("node_modules") {
                let parent = finding.path.parent().unwrap();
                assert_eq!(
                    fs.kind(&parent.join("package-lock.json")),
                    Some(Kind::File),
                    "seed {seed:#x} iteration {iteration} matched without a lockfile"
                );
            }
        }
        if mode == 1 {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.path.ends_with("node_modules") && finding.staged()),
                "seed {seed:#x} iteration {iteration} missed a locked, cold node_modules"
            );
        } else {
            assert!(
                report
                    .findings
                    .iter()
                    .all(|finding| !finding.path.ends_with("node_modules")),
                "seed {seed:#x} iteration {iteration} mode {mode} produced {:?}",
                report.findings
            );
        }
    }
}

#[test]
fn symlink_above_a_cache_is_followed_and_a_symlink_at_it_is_not() {
    let temp = TempDir::new("anchor");
    let root = fs::canonicalize(temp.path()).unwrap();
    let home = root.join("home");
    let disk = root.join("other-disk");
    let precious = root.join("precious");
    fs::create_dir_all(home.join("direct")).unwrap();
    fs::create_dir_all(disk.join("cache")).unwrap();
    fs::create_dir_all(&precious).unwrap();
    fs::write(disk.join("cache/blob"), b"refillable").unwrap();
    fs::write(precious.join("thesis.txt"), b"keep").unwrap();
    // `~/moved/cache` is a real directory on another disk.
    std::os::unix::fs::symlink(&disk, home.join("moved")).unwrap();
    // `~/direct/cache` is a link, and a link can name anything.
    std::os::unix::fs::symlink(&precious, home.join("direct/cache")).unwrap();
    set_tree_mtime(&root, old());

    let rules = [fixture_rule("moved/cache"), fixture_rule("direct/cache")];
    let report = scan(&ScanOptions {
        home: &home,
        roots: &[],
        safe_rules: &rules,
        project_rules: &[],
        deny: &deny_prefixes(&home, &[]),
        now: now(),
        git: &MapGit::default(),
        fs: &RealFs,
        progress: None,
        on_finding: None,
    })
    .expect("a scan worker can be spawned");

    let paths = report
        .findings
        .iter()
        .map(|finding| finding.path.clone())
        .collect::<Vec<_>>();
    assert_eq!(paths, [disk.join("cache")], "{:?}", report.findings);
}

/// xorshift64. The seed is printed when an assertion fails.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// Puts the mode back so [`TempDir`] can remove the fixture.
struct ModeGuard<'a>(&'a Path);

impl Drop for ModeGuard<'_> {
    fn drop(&mut self) {
        let _ = fs::set_permissions(self.0, fs::Permissions::from_mode(0o755));
    }
}

fn scan_fixture(home: &Path) -> Report {
    let git = MapGit::default();
    let fs = RealFs;
    let rules = [fixture_rule("cache")];
    let deny = deny_prefixes(home, &[]);
    scan(&ScanOptions {
        home,
        roots: &[],
        safe_rules: &rules,
        project_rules: &[],
        deny: &deny,
        now: now(),
        git: &git,
        fs: &fs,
        progress: None,
        on_finding: None,
    })
    .expect("a scan worker can be spawned")
}

#[test]
fn unlistable_cache_is_counted_and_not_a_finding() {
    let temp = TempDir::new("unlistable");
    let home = temp.path().join("home");
    let cache = home.join("cache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("blob"), b"data").unwrap();
    set_tree_mtime(&home, old());
    let _guard = ModeGuard(&cache);
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o000)).unwrap();

    let report = scan_fixture(&home);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(report.unreadable, 1);
}

#[test]
fn unlistable_child_is_partial_and_counted() {
    let temp = TempDir::new("partial");
    let home = temp.path().join("home");
    let cache = home.join("cache");
    let nested = cache.join("nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(cache.join("blob"), b"data").unwrap();
    set_tree_mtime(&home, old());
    let _guard = ModeGuard(&nested);
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o000)).unwrap();

    let report = scan_fixture(&home);
    assert_eq!(report.findings.len(), 1, "{:?}", report.findings);
    assert!(!report.findings[0].staged());
    assert_eq!(report.findings[0].skip, Some(Skip::Partial));
    assert_eq!(report.unreadable, 1);
}
