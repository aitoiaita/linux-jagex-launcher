use std::fmt::Display;

use reqwest::header::{CONTENT_TYPE, HeaderValue, AUTHORIZATION};
use serde::{Serialize, Deserialize};

use crate::daemon::LauncherIDToken;

const GAMESESSION_ACCOUNTS_ENDPOINT: &str = "https://auth.jagex.com/game-session/v1/accounts";
const GAMESESSION_SESSION_ENDPOINT: &str = "https://auth.jagex.com/game-session/v1/sessions";
const RS_PROFILE_ENDPOINT: &str = "https://secure.jagex.com/rs-profile/v1/profile";

#[derive(Debug)]
pub enum GameSessionError {
    JSON(serde_json::Error),
    HTTP(reqwest::Error),
    InvalidHeaderValue(reqwest::header::InvalidHeaderValue),
    URLParse(url::ParseError),
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

pub fn fetch_game_session(id_token: &LauncherIDToken) -> GameSessionResult<(SessionID, Vec<GameSessionAccount>)> {
    let http_client = reqwest::blocking::Client::new();

    let session_request_body = serde_json::to_string(&GameSessionRequest { id_token: id_token.clone() })?;
    let session_request = http_client.post(GAMESESSION_SESSION_ENDPOINT)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(session_request_body);

    let session_response = session_request.send()?.text().unwrap();
    let session: GameSession = serde_json::from_str(&session_response)?;
    
    let accounts_request = http_client.get(GAMESESSION_ACCOUNTS_ENDPOINT)
        .header(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", session.session_id().0))?);
    let accounts_response = accounts_request.send()?;
    let accounts = accounts_response.json()?;
    Ok((session.session_id, accounts))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionID(pub String);

#[derive(Clone, Serialize, Deserialize)]
pub struct GameSession {
    #[serde(rename = "sessionId")]
    session_id: SessionID
}

impl GameSession {
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