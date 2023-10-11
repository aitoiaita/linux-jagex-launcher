use std::{env::{self, VarError}, process::{Child, Command}, fmt::Display, path::PathBuf, fs::{File, OpenOptions}, io::Write};

use serde::{Serialize, de::DeserializeOwned};
use url::Url;

use crate::daemon::DAEMON_STATE_SUBDIR;

pub enum UrlOpenerError {
    IO(std::io::Error),
    SchemeIsntHttp
}
pub type UrlOpenerResult<T> = Result<T, UrlOpenerError>;

impl Display for UrlOpenerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlOpenerError::IO(e) => write!(f, "(IO error) {}", e),
            UrlOpenerError::SchemeIsntHttp => write!(f, "Url scheme isn't http/s"),
        }
    }
}

pub fn open_http_url(url: Url) -> UrlOpenerResult<Child> {
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(UrlOpenerError::SchemeIsntHttp);
    }
    Command::new("xdg-open")
        .arg(url.as_str())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(UrlOpenerError::IO)
}

#[derive(Debug)]
pub enum XDGDirectoryError {
    EnvVar(&'static str, VarError),
    CreateDir(std::io::Error),
}
pub type XDGDirectoryResult<T> = Result<T, XDGDirectoryError>;

impl Display for XDGDirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XDGDirectoryError::EnvVar(s, e) => write!(f, "Couldn't access env var \"{}\": {}", s, e),
            XDGDirectoryError::CreateDir(e) => write!(f, "Couldn't create XDG directory: {}", e),
        }
    }
}

pub fn home_env_var() -> XDGDirectoryResult<String> {
    env::var("HOME").map_err(|e| XDGDirectoryError::EnvVar("HOME", e) )
}

const XDG_STATE_HOME: &'static str = "XDG_STATE_HOME";
pub fn state_home() -> XDGDirectoryResult<PathBuf> {
    env::var(XDG_STATE_HOME)
        .or_else(|_| home_env_var().map(|home| format!("{}/.local/state", home) ) )
        .map(|ref s| PathBuf::from(s) )
}

pub fn ensure_state_home_exists(subdirectory: &str) -> XDGDirectoryResult<PathBuf> {
    let mut cur_path = PathBuf::new();
    let state_home_subdir = state_home()?.join(subdirectory);
    for component in state_home_subdir.components() {
        cur_path.push(component);
        if !cur_path.is_dir() {
            std::fs::create_dir(&cur_path)
                .map_err(XDGDirectoryError::CreateDir)?;
        }
    }
    Ok(cur_path)
}

#[derive(Debug)]
pub enum XDGCredsStateError {
    XDG(XDGDirectoryError),
    Open(std::io::Error), Write(std::io::Error), Read(std::io::Error),
    Serialize(serde_json::Error), Deserialize(serde_json::Error),
}
pub type XDGCredsStateResult<T> = Result<T, XDGCredsStateError>;

impl Display for XDGCredsStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XDGCredsStateError::XDG(e) => write!(f, "XDG directory error: {}", e),
            XDGCredsStateError::Open(e) => write!(f, "Couldn't open state file: {}", e),
            XDGCredsStateError::Write(e) => write!(f, "Couldn't write state file: {}", e),
            XDGCredsStateError::Read(e) => write!(f, "Couldn't read state file: {}", e),
            XDGCredsStateError::Serialize(e) => write!(f, "Couldn't serialize state file: {}", e),
            XDGCredsStateError::Deserialize(e) => write!(f, "Couldn't deserialize state file: {}", e),
        }
    }
}

pub trait XDGCredsState
where Self: Serialize + DeserializeOwned {
    const CREDS_FILENAME: &'static str;
    const STATE_SUBDIR: &'static str = DAEMON_STATE_SUBDIR;

    fn ensure_creds_file_path() -> XDGCredsStateResult<PathBuf> {
        ensure_state_home_exists(Self::STATE_SUBDIR)
            .map(|p| p.join(Self::CREDS_FILENAME) )
            .map_err(XDGCredsStateError::XDG)
    }

    fn from_state_file() -> XDGCredsStateResult<Option<Self>> {
        let creds_path = Self::ensure_creds_file_path()?;
        let creds_file = match File::open(creds_path) {
            Ok(f) => f,
            Err(e) => {
                if let std::io::ErrorKind::NotFound = e.kind() {
                    return Ok(None);
                } else {
                    return Err(XDGCredsStateError::Read(e));
                }
            }
        };
        let creds_data: Option<Self> = serde_json::from_reader(creds_file)
            .map_err(XDGCredsStateError::Deserialize)?;
        Ok(creds_data)
    }

    fn write_state_file(&self) -> XDGCredsStateResult<()> {
        let file_path = Self::ensure_creds_file_path()?;
        let file_exists = file_path.exists();
        let mut file = OpenOptions::new()
            .create_new(!file_exists)
            .write(true)
            .open(file_path)
            .map_err(XDGCredsStateError::Open)?;
        let data = serde_json::to_string(&Some(self)).map_err(XDGCredsStateError::Serialize)?;
        file.write_all(data.as_bytes()).map_err(XDGCredsStateError::Write)
    }
}