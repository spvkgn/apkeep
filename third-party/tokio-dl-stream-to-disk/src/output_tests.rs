use super::OutputDirectory;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn private_creation_pins_each_parent_and_rejects_existing_symlinks() {
    let fixture = tempfile::tempdir().unwrap();
    let original = fixture.path().join("out");
    let moved = fixture.path().join("moved");
    let victim = fixture.path().join("victim");
    fs::create_dir(&victim).unwrap();
    let output = OutputDirectory::create(&original).unwrap();
    fs::rename(&original, &moved).unwrap();
    symlink(&victim, &original).unwrap();
    let child = output
        .create_child(std::path::Path::new("config/cache"))
        .unwrap();
    fs::write(child.path().join("entry"), b"pinned").unwrap();
    assert_eq!(
        fs::metadata(moved.join("config/cache"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(fs::read_dir(&victim).unwrap().count(), 0);
    symlink(&victim, moved.join("link")).unwrap();
    assert!(output
        .create_child(std::path::Path::new("link/escape"))
        .is_err());
    assert!(OutputDirectory::create(&original.join("escape")).is_err());
    assert_eq!(fs::read_dir(&victim).unwrap().count(), 0);
}

#[test]
fn accepts_relative_and_dot_paths_without_changing_process_cwd() {
    let fixture = tempfile::Builder::new()
        .prefix("output-test-")
        .tempdir_in(".")
        .unwrap();
    let relative = fixture.path().strip_prefix(".").unwrap_or(fixture.path());
    let output = OutputDirectory::open(relative).unwrap();
    fs::write(output.path().join("file"), b"relative").unwrap();
    assert_eq!(fs::read(fixture.path().join("file")).unwrap(), b"relative");
    assert!(OutputDirectory::open(std::path::Path::new(".")).is_ok());
}

#[test]
fn rejects_missing_directories_regular_files_and_nul_components() {
    use std::os::unix::ffi::OsStrExt;
    let fixture = tempfile::tempdir().unwrap();
    assert!(OutputDirectory::open(&fixture.path().join("missing")).is_err());
    fs::write(fixture.path().join("file"), b"not a directory").unwrap();
    assert!(OutputDirectory::open(&fixture.path().join("file")).is_err());
    let nul = std::ffi::OsStr::from_bytes(b"bad\0name");
    assert!(OutputDirectory::open(&fixture.path().join(nul)).is_err());
}

#[test]
fn descriptors_are_close_on_exec() {
    use std::os::fd::AsRawFd;
    let fixture = tempfile::tempdir().unwrap();
    let output = OutputDirectory::open(fixture.path()).unwrap();
    // SAFETY: the descriptor is live and F_GETFD takes no additional argument.
    let flags = unsafe { libc::fcntl(output.directory.as_raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0);
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
}

#[test]
fn rejects_foreign_owned_final_and_ancestor_directories() {
    use std::os::fd::AsRawFd;
    // Changing ownership requires root; non-root runs retain all other checks.
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let foreign = fixture.path().join("foreign");
    fs::create_dir_all(foreign.join("child")).unwrap();
    let file = fs::File::open(&foreign).unwrap();
    // SAFETY: only this test's live directory descriptor is modified; -1 GID
    // leaves the group unchanged. The root-owned parent permits test cleanup.
    assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 65534, !0) }, 0);
    assert_eq!(
        OutputDirectory::open(&foreign).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        OutputDirectory::open(&foreign.join("child"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn cancellation_keeps_guard_alive_through_tempfile_cleanup_then_closes_it() {
    let fixture = tempfile::tempdir().unwrap();
    let original = fixture.path().join("output");
    fs::create_dir(&original).unwrap();
    let output = OutputDirectory::open(&original).unwrap();
    let descriptor_path = output.path().to_path_buf();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let temp = tempfile::NamedTempFile::new_in(output.path()).unwrap();
        fs::write(temp.path(), b"partial").unwrap();
        ready_tx.send(()).unwrap();
        std::future::pending::<()>().await;
        drop(temp);
        drop(output);
    });
    ready_rx.await.unwrap();
    assert_eq!(fs::read_dir(&original).unwrap().count(), 1);
    let moved = fixture.path().join("moved");
    fs::rename(&original, &moved).unwrap();
    let victim = fixture.path().join("victim");
    fs::create_dir(&victim).unwrap();
    fs::write(victim.join("sentinel"), b"untouched").unwrap();
    symlink(&victim, &original).unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
    assert_eq!(fs::read(victim.join("sentinel")).unwrap(), b"untouched");
    // A concurrent test may reuse the descriptor number, but not this inode.
    assert_ne!(
        fs::read_link(descriptor_path).ok().as_deref(),
        Some(moved.as_path())
    );
}

#[test]
fn rejects_symlinks_in_every_position_and_parent_traversal() {
    let fixture = tempfile::tempdir().unwrap();
    let real = fixture.path().join("real");
    fs::create_dir_all(real.join("child")).unwrap();
    let link = fixture.path().join("link");
    symlink(&real, &link).unwrap();
    assert!(OutputDirectory::open(&link).is_err(), "final symlink");
    assert!(
        OutputDirectory::open(&link.join("child")).is_err(),
        "ancestor symlink"
    );
    assert!(
        OutputDirectory::open(&real.join("child/../child")).is_err(),
        "parent traversal"
    );
    assert!(
        OutputDirectory::open(std::path::Path::new("")).is_err(),
        "empty path"
    );
}

#[test]
fn rejects_group_or_other_writable_final_directory_even_if_sticky() {
    let fixture = tempfile::tempdir().unwrap();
    for mode in [0o770, 0o707, 0o1777] {
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(mode)).unwrap();
        let result = OutputDirectory::open(fixture.path());
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err(), "accepted unsafe final mode {mode:o}");
    }
}

#[test]
fn rejects_unprotected_writable_ancestor_but_accepts_sticky_ancestor() {
    let fixture = tempfile::tempdir().unwrap();
    let shared = fixture.path().join("shared");
    let child = shared.join("private");
    fs::create_dir_all(&child).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(OutputDirectory::open(&child).is_err());
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(OutputDirectory::open(&child).is_ok());
}

#[test]
fn child_handles_survive_parent_drop_and_reject_unsafe_children() {
    let fixture = tempfile::tempdir().unwrap();
    fs::create_dir_all(fixture.path().join("child/nested")).unwrap();
    let output = OutputDirectory::open(fixture.path()).unwrap();
    let child = output
        .open_child(std::path::Path::new("child/nested"))
        .unwrap();
    assert!(output.open_child(std::path::Path::new("../child")).is_err());
    assert!(output.open_child(fixture.path()).is_err());
    assert!(output.open_child(std::path::Path::new("")).is_err());
    symlink("child", output.path().join("link")).unwrap();
    assert!(output
        .open_child(std::path::Path::new("link/nested"))
        .is_err());
    fs::set_permissions(
        fixture.path().join("child/nested"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(output
        .open_child(std::path::Path::new("child/nested"))
        .is_err());
    fs::set_permissions(
        fixture.path().join("child/nested"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    drop(output);
    fs::write(child.path().join("file"), b"child").unwrap();
    assert_eq!(
        fs::read(fixture.path().join("child/nested/file")).unwrap(),
        b"child"
    );
    assert!(
        OutputDirectory::open(child.path()).is_err(),
        "do not repin procfs symlinks"
    );
}

#[test]
fn unavailable_or_fake_procfs_fails_closed() {
    let fixture = tempfile::tempdir().unwrap();
    let fd = || std::os::fd::OwnedFd::from(fs::File::open(fixture.path()).unwrap());
    let missing = fixture.path().join("missing");
    assert!(super::linux::finish_at(fd(), &missing).is_err());
    let fake = fixture.path().join("fake-proc-fd");
    fs::create_dir(&fake).unwrap();
    assert_eq!(
        super::linux::finish_at(fd(), &fake).unwrap_err().kind(),
        std::io::ErrorKind::Unsupported
    );
}

#[test]
fn pinned_directory_survives_ancestor_rename_without_victim_writes_or_clobber() {
    let fixture = tempfile::tempdir().unwrap();
    let ancestor = fixture.path().join("ancestor");
    let original = ancestor.join("output");
    fs::create_dir_all(&original).unwrap();
    let victim = fixture.path().join("victim");
    let victim_output = victim.join("output");
    fs::create_dir_all(&victim_output).unwrap();
    fs::write(victim_output.join("already.apk"), b"victim").unwrap();
    let output = OutputDirectory::open(&original).unwrap();
    let moved = fixture.path().join("moved");
    fs::rename(&ancestor, &moved).unwrap();
    symlink(&victim, &ancestor).unwrap();
    fs::write(output.path().join("new.apk"), b"download").unwrap();
    fs::write(output.path().join("already.apk"), b"original directory").unwrap();
    assert_eq!(fs::read(moved.join("output/new.apk")).unwrap(), b"download");
    assert_eq!(
        fs::read(victim_output.join("already.apk")).unwrap(),
        b"victim"
    );
    assert!(!victim_output.join("new.apk").exists());
    assert_eq!(fs::read_dir(&victim_output).unwrap().count(), 1);
}
