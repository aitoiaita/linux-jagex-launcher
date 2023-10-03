use std::{fmt::Display, path::PathBuf, fs::{File, OpenOptions}, io::Write};

use reqwest::header::{CONTENT_TYPE, HeaderValue, AUTHORIZATION};
use serde::{Serialize, Deserialize};

use crate::{daemon::{LauncherIDToken, DaemonResult, DaemonError}, xdg::{XDGDirectoryError, self}};

const GAMESESSION_ACCOUNTS_ENDPOINT: &str = "https://auth.jagex.com/game-session/v1/accounts";
const GAMESESSION_SESSION_ENDPOINT: &str = "https://auth.jagex.com/game-session/v1/sessions";
const RS_PROFILE_ENDPOINT: &str = "https://secure.jagex.com/rs-profile/v1/profile";

#[derive(Debug)]
pub enum GameSessionError {
    JSON(serde_json::Error),
    HTTP(reqwest::Error),
    InvalidHeaderValue(reqwest::header::InvalidHeaderValue),
    URLParse(url::ParseError),
    SerializeCreds(serde_json::Error),
    WriteCreds(std::io::Error),
    XDG(XDGDirectoryError),
    ReadCreds(std::io::Error),
    DeserializeCreds(serde_json::Error),
}
type GameSessionResult<T> = Result<T, GameSessionError>;

impl From<serde_json::Error> for GameSessionError {
    fn from(e: serde_json::Error) -> Self {
        GameSessionError::JSON(e)
    }
}

impl From<reqwest::Error> for GameSessionError {
    fn from(e: reqwest::Error) -> Self {
        GameSessionError::HTTP(e)
    }
}

impl From<reqwest::header::InvalidHeaderValue> for GameSessionError {
    fn from(e: reqwest::header::InvalidHeaderValue) -> Self {
        GameSessionError::InvalidHeaderValue(e)
    }
}

impl From<url::ParseError> for GameSessionError {
    fn from(e: url::ParseError) -> Self {
        GameSessionError::URLParse(e)
    }
}

impl Display for GameSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GameSessionError::JSON(e) => write!(f, "Error parsing JSON: {}", e),
            GameSessionError::HTTP(e) => write!(f, "HTTP error: {}", e),
            GameSessionError::InvalidHeaderValue(e) => write!(f, "{}", e),
            GameSessionError::URLParse(e) => write!(f, "Error parsing URL: {}", e),
            GameSessionError::SerializeCreds(e) => write!(f, "Couldn't serialize credentials: {}", e),
            GameSessionError::WriteCreds(e) => write!(f, "Couldn't save credentials: {}", e),
            GameSessionError::XDG(e) => write!(f, "XDG environment error: {}", e),
            GameSessionError::ReadCreds(e) => write!(f, "Couldn't read saved credentials: {}", e),
            GameSessionError::DeserializeCreds(e) => write!(f, "Couldn't deserialize saved credentials: {}", e),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RSProfileResponse {
    pub display_name_set: bool,
    pub display_name: Option<String>,
}

pub fn fetch_game_profile(id_token: &LauncherIDToken) -> GameSessionResult<RSProfileResponse> {
    let http_client = reqwest::blocking::Client::new();
    let request = http_client.get(RS_PROFILE_ENDPOINT)
        .header(AUTHORIZATION, format!("Bearer {}", id_token.original));
    let response = request.send()?.text().unwrap();
    let profile = serde_json::from_str(&response)?;
    Ok(profile)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionID(pub String);

#[derive(Clone, Serialize, Deserialize)]
pub struct GameSessionID {
    #[serde(rename = "sessionId")]
    session_id: SessionID
}

impl GameSessionID {
    pub fn session_id(&self) -> &SessionID {
        &self.session_id
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct GameSessionRequest {
    #[serde(rename = "idToken")]
    id_token: LauncherIDToken
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccountID(pub String);
#[derive(Clone, Serialize, Deserialize)]
pub struct DisplayName(pub String);

#[derive(Clone, Serialize, Deserialize)]
pub struct GameSessionAccount {
    #[serde(rename = "accountId")]
    pub account_id: AccountID,
    #[serde(rename = "displayName")]
    pub display_name: DisplayName
}

#[derive(Serialize, Deserialize)]
pub struct GameSession {
    pub session_id: GameSessionID,
    pub accounts: Vec<GameSessionAccount>,
}

impl GameSession {
    fn new(session_id: GameSessionID, accounts: Vec<GameSessionAccount>) -> Self {
        GameSession { session_id, accounts }
    }
}

pub fn fetch_game_session(id_token: &LauncherIDToken) -> GameSessionResult<GameSession> {
    let http_client = reqwest::blocking::Client::new();

    let session_request_body = serde_json::to_string(&GameSessionRequest { id_token: id_token.clone() })?;
    let session_request = http_client.post(GAMESESSION_SESSION_ENDPOINT)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(session_request_body);

    let session_id_response = session_request.send()?.text().unwrap();
    let session_id: GameSessionID = serde_json::from_str(&session_id_response)?;
    
    let accounts_request = http_client.get(GAMESESSION_ACCOUNTS_ENDPOINT)
        .header(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", session_id.session_id().0))?);
    let accounts_response = accounts_request.send()?;
    let accounts = accounts_response.json()?;

    let game_session = GameSession::new(session_id, accounts);
    Ok(game_session)
}

#[derive(Serialize, Deserialize)]
pub enum AccountSession {
    Runescape { profile: RSProfileResponse },
    Jagex { session_id: GameSessionID, accounts: Vec<GameSessionAccount> },
}

impl AccountSession {
    const STATE_FILENAME: &'static str = "account_session.json";
    pub fn ensure_state_file_path() -> GameSessionResult<PathBuf> {
        let xdg_dir = xdg::ensure_state_home_exists()
            .map_err(GameSessionError::XDG)?;
        Ok(xdg_dir.join(Self::STATE_FILENAME))
    }

    pub fn from_state_file() -> GameSessionResult<Option<Self>> {
        let creds_path = Self::ensure_state_file_path()?;
        let creds_file = match File::open(creds_path) {
            Ok(f) => f,
            Err(e) => {
                if let std::io::ErrorKind::NotFound = e.kind() {
                    return Ok(None);
                } else {
                    return Err(GameSessionError::ReadCreds(e));
                }
            }
        };
        let creds_data: Option<Self> = serde_json::from_reader(creds_file)
            .map_err(GameSessionError::DeserializeCreds)?;
        Ok(creds_data)
    }

    pub fn write_state_file(&self) -> GameSessionResult<()> {
        let file_path = Self::ensure_state_file_path()?;
        let file_exists = file_path.exists();
        let mut file = OpenOptions::new()
            .create_new(!file_exists)
            .write(true)
            .open(file_path)
            .map_err(GameSessionError::WriteCreds)?;
        let data = serde_json::to_string(&Some(&self))
            .map_err(GameSessionError::SerializeCreds)?;
        file.write_all(data.as_bytes())
            .map_err(GameSessionError::WriteCreds)?;
        Ok(())
    }
}

pub struct GameSessionClient {
    pub session: Option<AccountSession>,
}

impl GameSessionClient {
    pub fn new() -> DaemonResult<Self> {
        let session = AccountSession::from_state_file()
            .map_err(DaemonError::GameSessionClient)?;
        Ok(GameSessionClient { session })
    }

    pub fn set_saved_session<'a>(&'a mut self, session: AccountSession) -> GameSessionResult<&'a AccountSession> {
        session.write_state_file()?;
        self.session = Some(session);
        Ok(self.session.as_ref().unwrap())
    }
}