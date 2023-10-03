use std::{env::{self, VarError}, process::{Child, Command}, fmt::Display, path::PathBuf};

use url::Url;

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

const HOME: &'static str = "HOME";

const XDG_DATA_HOME: &'static str = "XDG_DATA_HOME";
pub fn data_home() -> XDGDirectoryResult<PathBuf> {
    env::var(XDG_DATA_HOME)
        .or_else(|_| env::var(HOME).map(|home| format!("{}/.local/share", home) ) )
        .map_err(|e| XDGDirectoryError::EnvVar(HOME, e) )
        .map(|ref s| PathBuf::from(s) )
}

const XDG_CONFIG_HOME: &'static str = "XDG_CONFIG_HOME";
pub fn config_home() -> XDGDirectoryResult<PathBuf> {
    env::var(XDG_CONFIG_HOME)
        .or_else(|_| env::var(HOME).map(|home| format!("{}/.config", home) ) )
        .map_err(|e| XDGDirectoryError::EnvVar(HOME, e) )
        .map(|ref s| PathBuf::from(s) )
}

const XDG_STATE_HOME: &'static str = "XDG_STATE_HOME";
pub fn state_home() -> XDGDirectoryResult<PathBuf> {
    env::var(XDG_STATE_HOME)
        .or_else(|_| env::var(HOME).map(|home| format!("{}/.local/state", home) ) )
        .map_err(|e| XDGDirectoryError::EnvVar(HOME, e) )
        .map(|ref s| PathBuf::from(s) )
}

pub fn ensure_state_home_exists() -> XDGDirectoryResult<PathBuf> {
    let mut cur_path = PathBuf::new();
    for component in state_home()?.components() {
        cur_path.push(component);
        if !cur_path.is_dir() {
            std::fs::create_dir(&cur_path)
                .map_err(XDGDirectoryError::CreateDir)?;
        }
    }
    Ok(cur_path)
}