use super::*;

#[cfg(unix)]
#[test]
fn config_creation_rejects_symlink_parent_before_creating_children() {
    let root = tempfile::tempdir().unwrap();
    let victim = root.path().join("victim");
    fs::create_dir(&victim).unwrap();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    assert!(create_dir(&link.join("apkeep")).is_err());
    assert_eq!(fs::read_dir(&victim).unwrap().count(), 0);
}

#[test]
fn creates_missing_directory_and_preserves_existing_contents() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config");
    create_dir(&path).unwrap();
    assert!(path.is_dir());
    let marker = path.join("apkeep.ini");
    fs::write(&marker, b"existing configuration").unwrap();
    create_dir(&path).unwrap();
    assert_eq!(fs::read(marker).unwrap(), b"existing configuration");
}

#[test]
fn file_in_place_of_directory_is_not_overwritten() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("file");
    fs::write(&path, b"keep").unwrap();
    assert!(matches!(
        create_dir(&path),
        Err(ConfigDirError::CouldNotCreate)
    ));
    assert_eq!(fs::read(&path).unwrap(), b"keep");
}

#[test]
fn missing_parent_directories_are_created_recursively() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("missing").join("nested").join("apkeep");
    create_dir(&path).unwrap();
    assert!(path.is_dir());
}

#[test]
fn error_messages_are_stable_and_implement_error() {
    for (error, message) in [
        (ConfigDirError::NotFound, "NotFound"),
        (ConfigDirError::CouldNotCreate, "CouldNotCreate"),
    ] {
        let error: &dyn Error = &error;
        assert_eq!(error.to_string(), message);
        assert!(error.source().is_none());
    }
}
