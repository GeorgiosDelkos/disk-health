//! Apply, restore, and purge. These tests fail if a staged path is moved
//! after its inode changes, if a wrong confirm is ignored, or if `EXDEV`
//! turns into a copy or an unlink. Nothing here uses the real home directory.

use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

use disk_health::config::deny_prefixes;
use disk_health::log::{Action, ActionLog, MemoryLog};
use disk_health::plan::{Entry, Plan};
use disk_health::rules::Tier;
use disk_health::time::{from_unix_nanos, unix_nanos};
use disk_health::trash::{
    ApplyReport, ApplyRequest, FsRename, PurgeRequest, Renamer, RestoreRequest, SkipMove, apply,
    purge, restore,
};
use disk_health::walk::{Fs, Kind, RealFs, measure};

#[allow(
    clippy::duration_suboptimal_units,
    reason = "fixed unix timestamp used as the scan clock"
)]
fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000)
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

struct Recorded(Mutex<Vec<(PathBuf, PathBuf)>>);

impl Renamer for Recorded {
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0
            .lock()
            .expect("rename log")
            .push((from.to_path_buf(), to.to_path_buf()));
        Ok(())
    }
}

impl Recorded {
    fn calls(&self) -> usize {
        self.0.lock().expect("rename log").len()
    }
}

struct Exdev;

impl Renamer for Exdev {
    fn rename(&self, _from: &Path, _to: &Path) -> std::io::Result<()> {
        Err(std::io::Error::new(ErrorKind::CrossesDevices, "exdev"))
    }
}

fn set_mtime(path: &Path, nanos: u128) {
    let when = from_unix_nanos(nanos).expect("mtime is after the epoch");
    File::open(path)
        .expect("fixture can be opened")
        .set_modified(when)
        .expect("mtime can be set");
}

fn entry_at(path: &Path, staged: bool, marker: Option<PathBuf>) -> Entry {
    let fs = RealFs;
    let meta = fs.meta(path).expect("fixture can be stated");
    let newest = if meta.kind == Kind::Directory {
        measure(&fs, path, &meta)
            .expect("fixture can be measured")
            .newest
            .and_then(unix_nanos)
    } else {
        meta.mtime.and_then(unix_nanos)
    };
    Entry {
        rule: "fixture".to_owned(),
        tier: Tier::Safe,
        path: path.to_path_buf(),
        dev: meta.dev,
        ino: meta.ino,
        mtime_ns: meta.mtime.and_then(unix_nanos),
        newest_child_ns: newest,
        apparent_bytes: meta.len,
        staged,
        regenerate: None,
        marker,
    }
}

fn apply_real(
    plan: &Plan,
    confirm: &str,
    home: &Path,
    renamer: &dyn Renamer,
    log: &mut MemoryLog,
) -> disk_health::Result<ApplyReport> {
    let home_dev = RealFs.meta(home).expect("home can be stated").dev;
    apply(ApplyRequest {
        plan,
        confirm,
        home,
        home_dev,
        uid: 501,
        deny: &deny_prefixes(home, &[]),
        fs: &RealFs,
        renamer,
        log,
        now: now(),
        interrupt: None,
    })
}

#[test]
fn replaced_inode_is_not_moved() {
    let fixture = TempDir::new("inode");
    let home = fixture.path().join("home");
    let cache = home.join("cache");
    fs::create_dir_all(&cache).unwrap();
    let blob = cache.join("blob");
    fs::write(&blob, b"keep").unwrap();
    let old = now() - Duration::from_hours(48);
    set_mtime(&blob, unix_nanos(old).unwrap());
    set_mtime(&cache, unix_nanos(old).unwrap());
    let entry = entry_at(&cache, true, None);

    fs::remove_dir_all(&cache).unwrap();
    fs::create_dir_all(&cache).unwrap();
    fs::write(&blob, b"replaced").unwrap();
    set_mtime(&blob, entry.newest_child_ns.unwrap());
    set_mtime(&cache, entry.mtime_ns.unwrap());

    let plan = Plan::from_entries(vec![entry], "host", now());
    let renamer = Recorded(Mutex::new(Vec::new()));
    let mut log = MemoryLog::default();
    let report = apply_real(&plan, &plan.plan_id, &home, &renamer, &mut log).unwrap();

    assert_eq!(fs::read(&blob).unwrap(), b"replaced");
    assert_eq!(renamer.calls(), 0);
    assert!(matches!(report.skipped[0].reason, SkipMove::Identity));
    assert_eq!(report.exit_code(), 3);
    assert_eq!(log.actions(), []);
}

#[test]
fn newer_child_is_not_moved() {
    let fixture = TempDir::new("newer");
    let home = fixture.path().join("home");
    let cache = home.join("cache");
    fs::create_dir_all(&cache).unwrap();
    let blob = cache.join("blob");
    fs::write(&blob, b"old").unwrap();
    let old = now() - Duration::from_hours(48);
    set_mtime(&blob, unix_nanos(old).unwrap());
    set_mtime(&cache, unix_nanos(old).unwrap());
    let entry = entry_at(&cache, true, None);

    let fresh = cache.join("fresh");
    fs::write(&fresh, b"new").unwrap();
    // The file's own clock is the wall clock. The plan clock is fixed, so the
    // child has to be stamped or it can be older than the scan.
    set_mtime(&fresh, unix_nanos(now()).unwrap());
    set_mtime(&cache, entry.mtime_ns.unwrap());

    let plan = Plan::from_entries(vec![entry], "host", now());
    let renamer = Recorded(Mutex::new(Vec::new()));
    let mut log = MemoryLog::default();
    let report = apply_real(&plan, &plan.plan_id, &home, &renamer, &mut log).unwrap();

    assert!(cache.join("fresh").exists());
    assert_eq!(renamer.calls(), 0);
    assert!(
        matches!(report.skipped[0].reason, SkipMove::Newer),
        "{:?}",
        report.skipped
    );
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn wrong_confirm_moves_nothing() {
    let fixture = TempDir::new("confirm");
    let home = fixture.path().join("home");
    let cache = home.join("cache");
    fs::create_dir_all(&home).unwrap();
    fs::write(&cache, b"keep").unwrap();
    let plan = Plan::from_entries(vec![entry_at(&cache, true, None)], "host", now());
    let renamer = Recorded(Mutex::new(Vec::new()));
    let mut log = MemoryLog::default();
    let err = apply_real(&plan, "not-the-id", &home, &renamer, &mut log).unwrap_err();

    assert!(err.to_string().contains("does not match"), "{err}");
    assert_eq!(fs::read(&cache).unwrap(), b"keep");
    assert_eq!(renamer.calls(), 0);
    assert_eq!(log.actions(), []);
}

#[test]
fn exdev_leaves_the_source_bytes_in_place() {
    let fixture = TempDir::new("exdev");
    let home = fixture.path().join("home");
    let cache = home.join("cache");
    fs::create_dir_all(&home).unwrap();
    fs::write(&cache, b"keep-me").unwrap();
    let plan = Plan::from_entries(vec![entry_at(&cache, true, None)], "host", now());
    let mut log = MemoryLog::default();
    let report = apply_real(&plan, &plan.plan_id, &home, &Exdev, &mut log).unwrap();

    assert_eq!(fs::read(&cache).unwrap(), b"keep-me");
    assert!(
        matches!(report.skipped[0].reason, SkipMove::Exdev),
        "{:?}",
        report.skipped
    );
    assert_eq!(log.actions(), []);
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn rename_keeps_the_inode_and_restore_puts_it_back() {
    let fixture = TempDir::new("rename");
    let home = fixture.path().join("home");
    let cache = home.join("cache");
    fs::create_dir_all(&home).unwrap();
    fs::write(&cache, b"bytes").unwrap();
    let entry = entry_at(&cache, true, None);
    let inode = entry.ino;
    let plan = Plan::from_entries(vec![entry], "host", now());
    let mut log = MemoryLog::default();
    let report = apply_real(&plan, &plan.plan_id, &home, &FsRename, &mut log).unwrap();

    assert!(!cache.exists(), "{:?}", report.skipped);
    assert_eq!(report.exit_code(), 0, "{:?}", report.skipped);
    let moved = &report.moved[0];
    assert!(moved.to.starts_with(home.join(".Trash")));
    assert_eq!(RealFs.meta(&moved.to).unwrap().ino, inode);
    assert_eq!(fs::read(&moved.to).unwrap(), b"bytes");
    assert!(moved.logged);

    let restored = restore(&RestoreRequest {
        id: &moved.id,
        home: &home,
        uid: 501,
        log: &log,
        renamer: &FsRename,
    })
    .unwrap();
    assert_eq!(restored, cache);
    assert_eq!(fs::read(&cache).unwrap(), b"bytes");
}

#[test]
fn restore_does_not_clobber_an_existing_path() {
    let fixture = TempDir::new("clobber");
    let home = fixture.path().join("home");
    let cache = home.join("cache");
    let trashed = home.join(".Trash").join("cache");
    fs::create_dir_all(home.join(".Trash")).unwrap();
    fs::write(&cache, b"original").unwrap();
    fs::write(&trashed, b"trashed").unwrap();
    let action = Action {
        id: String::new(),
        plan_id: "plan".to_owned(),
        rule: "fixture".to_owned(),
        from: cache.clone(),
        to: trashed.clone(),
        dev: 1,
        ino: 2,
        apparent_bytes: 8,
        at: now(),
    }
    .stamp();
    let mut log = MemoryLog::default();
    log.append(&action).unwrap();

    let err = restore(&RestoreRequest {
        id: &action.id,
        home: &home,
        uid: 501,
        log: &log,
        renamer: &FsRename,
    })
    .unwrap_err();

    assert!(err.to_string().contains("original path exists"), "{err}");
    assert_eq!(fs::read(&cache).unwrap(), b"original");
    assert_eq!(fs::read(&trashed).unwrap(), b"trashed");
}

#[test]
fn purge_ignores_a_row_outside_quarantine() {
    let fixture = TempDir::new("purge");
    let quarantine = fixture
        .path()
        .join("vol")
        .join(".disk-health-quarantine")
        .join("plan");
    fs::create_dir_all(&quarantine).unwrap();
    let inside = quarantine.join("old");
    let young = quarantine.join("young");
    let outside = fixture.path().join("keep");
    fs::write(&inside, b"gone").unwrap();
    fs::write(&young, b"stay-young").unwrap();
    fs::write(&outside, b"stay").unwrap();

    let old = now() - Duration::from_hours(8 * 24);
    let recent = now() - Duration::from_hours(2);
    let mut log = MemoryLog::default();
    for (path, at) in [(&inside, old), (&young, recent), (&outside, old)] {
        log.append(&logged(path, at)).unwrap();
    }

    let report = purge(&PurgeRequest {
        log: &log,
        now: now(),
    })
    .unwrap();
    assert!(!inside.exists());
    assert_eq!(fs::read(&young).unwrap(), b"stay-young");
    assert_eq!(fs::read(&outside).unwrap(), b"stay");
    assert_eq!(report.removed, vec![inside]);
}

#[test]
fn unstaged_entry_is_not_a_failure() {
    let fixture = TempDir::new("unstaged");
    let home = fixture.path().join("home");
    let cache = home.join("cache");
    fs::create_dir_all(&home).unwrap();
    fs::write(&cache, b"keep").unwrap();
    let plan = Plan::from_entries(vec![entry_at(&cache, false, None)], "host", now());
    let renamer = Recorded(Mutex::new(Vec::new()));
    let mut log = MemoryLog::default();
    let report = apply_real(&plan, &plan.plan_id, &home, &renamer, &mut log).unwrap();

    assert_eq!(report.exit_code(), 0);
    assert_eq!(renamer.calls(), 0);
    assert_eq!(fs::read(&cache).unwrap(), b"keep");
}

#[test]
fn denied_plan_path_is_not_moved() {
    let fs = disk_health::walk::MemFs::new();
    let when = now() - Duration::from_hours(48);
    fs.dir("/System/secret", 1, when);
    let meta = fs.meta(Path::new("/System/secret")).unwrap();
    let entry = Entry {
        rule: "fixture".to_owned(),
        tier: Tier::Safe,
        path: PathBuf::from("/System/secret"),
        dev: meta.dev,
        ino: meta.ino,
        mtime_ns: meta.mtime.and_then(unix_nanos),
        newest_child_ns: meta.mtime.and_then(unix_nanos),
        apparent_bytes: 1,
        staged: true,
        regenerate: None,
        marker: None,
    };
    let plan = Plan::from_entries(vec![entry], "host", now());
    let home = PathBuf::from("/Users/ada");
    let deny = deny_prefixes(&home, &[]);
    let renamer = Recorded(Mutex::new(Vec::new()));
    let mut log = MemoryLog::default();
    let report = apply(ApplyRequest {
        plan: &plan,
        confirm: &plan.plan_id,
        home: &home,
        home_dev: 1,
        uid: 501,
        deny: &deny,
        fs: &fs,
        renamer: &renamer,
        log: &mut log,
        now: now(),
        interrupt: None,
    })
    .unwrap();

    assert_eq!(renamer.calls(), 0);
    assert!(matches!(report.skipped[0].reason, SkipMove::Denied));
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn caution_without_a_marker_is_not_moved() {
    let fixture = TempDir::new("marker");
    let home = fixture.path().join("home");
    let cache = home.join("target");
    fs::create_dir_all(&home).unwrap();
    fs::write(&cache, b"obj").unwrap();
    let mut entry = entry_at(&cache, true, None);
    entry.tier = Tier::Caution;
    let plan = Plan::from_entries(vec![entry], "host", now());
    let renamer = Recorded(Mutex::new(Vec::new()));
    let mut log = MemoryLog::default();
    let report = apply_real(&plan, &plan.plan_id, &home, &renamer, &mut log).unwrap();

    assert_eq!(fs::read(&cache).unwrap(), b"obj");
    assert_eq!(renamer.calls(), 0);
    assert!(matches!(report.skipped[0].reason, SkipMove::Marker));
}

#[test]
fn interrupt_stops_before_a_rename() {
    let fixture = TempDir::new("interrupt");
    let home = fixture.path().join("home");
    let cache = home.join("cache");
    fs::create_dir_all(&home).unwrap();
    fs::write(&cache, b"keep").unwrap();
    let plan = Plan::from_entries(vec![entry_at(&cache, true, None)], "host", now());
    let flag = AtomicBool::new(true);
    let renamer = Recorded(Mutex::new(Vec::new()));
    let mut log = MemoryLog::default();
    let home_dev = RealFs.meta(&home).unwrap().dev;
    let deny = deny_prefixes(&home, &[]);
    let report = apply(ApplyRequest {
        plan: &plan,
        confirm: &plan.plan_id,
        home: &home,
        home_dev,
        uid: 501,
        deny: &deny,
        fs: &RealFs,
        renamer: &renamer,
        log: &mut log,
        now: now(),
        interrupt: Some(&flag),
    })
    .unwrap();

    assert_eq!(fs::read(&cache).unwrap(), b"keep");
    assert_eq!(renamer.calls(), 0);
    assert!(matches!(report.skipped[0].reason, SkipMove::Interrupted));
}

fn logged(path: &Path, at: SystemTime) -> Action {
    Action {
        id: String::new(),
        plan_id: "plan".to_owned(),
        rule: "fixture".to_owned(),
        from: PathBuf::from("/cache"),
        to: path.to_path_buf(),
        dev: 1,
        ino: 2,
        apparent_bytes: 4,
        at,
    }
    .stamp()
}
