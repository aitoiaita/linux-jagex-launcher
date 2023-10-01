use std::{env::{self, VarError}, process::{Child, Command}, fmt::Display};

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

pub fn data_home() -> Result<String, VarError> {
    env::var("XDG_DATA_HOME")
        .or_else(|_| env::var("HOME").map(|home| format!("{}/.local/share", home) ) )
}

pub fn config_home() -> Result<String, VarError> {
    env::var("XDG_CONFIG_HOME")
        .or_else(|_| env::var("HOME").map(|home| format!("{}/.config", home) ) )
}

pub fn state_home() -> Result<String, VarError> {
    env::var("XDG_STATE_HOME")
        .or_else(|_| env::var("HOME").map(|home| format!("{}/.local/state", home) ) )
}