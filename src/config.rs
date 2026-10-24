use std::error::Error;
use std::fmt;
#[cfg(test)]
use std::fs;
use std::path::PathBuf;
use tokio_dl_stream_to_disk::OutputDirectory;

#[derive(Debug)]
pub enum ConfigDirError {
    NotFound,
    CouldNotCreate,
}

impl Error for ConfigDirError {}

impl fmt::Display for ConfigDirError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "NotFound"),
            Self::CouldNotCreate => write!(f, "CouldNotCreate"),
        }
    }
}

#[cfg(test)]
pub fn create_dir(config_dir: &std::path::Path) -> Result<(), ConfigDirError> {
    OutputDirectory::create(config_dir).map_err(|_| ConfigDirError::CouldNotCreate)?;
    Ok(())
}

pub fn config_directory() -> Result<OutputDirectory, ConfigDirError> {
    let base = dirs::config_dir().ok_or(ConfigDirError::NotFound)?;
    let parent = OutputDirectory::create(&base).map_err(|_| ConfigDirError::CouldNotCreate)?;
    parent
        .create_child(std::path::Path::new("apkeep"))
        .map_err(|_| ConfigDirError::CouldNotCreate)
}

pub fn config_dir() -> Result<PathBuf, ConfigDirError> {
    let mut config_dir = dirs::config_dir().ok_or(ConfigDirError::NotFound)?;
    let _guard = config_directory()?;
    config_dir.push("apkeep");
    Ok(config_dir)
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
