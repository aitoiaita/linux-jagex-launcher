use std::{fmt::Display, sync::LazyLock};

use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};

use crate::{
    daemon::LauncherIDToken,
    trans_tuple_struct,
    xdg::{XDGCredsState, XDGCredsStateError},
};

const GAMESESSION_ACCOUNTS_ENDPOINT: &str = "https://auth.jagex.com/game-session/v1/accounts";
const GAMESESSION_SESSION_ENDPOINT: &str = "https://auth.jagex.com/game-session/v1/sessions";
const RS_PROFILE_ENDPOINT: &str = "https://secure.jagex.com/rs-profile/v1/profile";

#[derive(Debug)]
pub enum GameSessionError {
    JSON(serde_json::Error),
    HTTP(reqwest::Error),
    InvalidHeaderValue(reqwest::header::InvalidHeaderValue),
    URLParse(url::ParseError),
    CredsState(XDGCredsStateError),
}
type GameSessionResult<T> = Result<T, GameSessionError>;

impl From<XDGCredsStateError> for GameSessionError {
    fn from(e: XDGCredsStateError) -> Self {
        GameSessionError::CredsState(e)
    }
}

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
            GameSessionError::CredsState(e) => write!(f, "Saved credential error: {}", e),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RSProfileResponse {
    pub display_name_set: bool,
    pub display_name: Option<String>,
}

impl RSProfileResponse {
    pub fn get_display_name<'a>(&'a self) -> &'a Option<String> {
        &self.display_name
    }
}

pub fn fetch_game_profile(id_token: &LauncherIDToken) -> GameSessionResult<RSProfileResponse> {
    let http_client = reqwest::blocking::Client::new();
    let request = http_client
        .get(RS_PROFILE_ENDPOINT)
        .header(AUTHORIZATION, format!("Bearer {}", id_token.original));
    let response = request.send()?.text().unwrap();
    let profile = serde_json::from_str(&response)?;
    Ok(profile)
}

trans_tuple_struct!(pub SessionID(String), derive(Debug, Clone, Serialize, Deserialize));

#[derive(Clone, Serialize, Deserialize)]
pub struct GameSessionID {
    #[serde(rename = "sessionId")]
    session_id: SessionID,
}

impl GameSessionID {
    pub fn session_id(&self) -> &SessionID {
        &self.session_id
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct GameSessionRequest {
    #[serde(rename = "idToken")]
    id_token: LauncherIDToken,
}

trans_tuple_struct!(pub AccountID(String), derive(Clone, Serialize, Deserialize));
trans_tuple_struct!(pub DisplayName(String), derive(Clone, Serialize, Deserialize));

#[derive(Clone, Serialize, Deserialize)]
pub struct GameSessionAccount {
    #[serde(rename = "accountId")]
    account_id: AccountID,
    #[serde(rename = "displayName", default)]
    display_name: Option<DisplayName>,
    #[serde(rename = "userHash")]
    user_hash: String,
}

impl GameSessionAccount {
    pub fn get_display_name<'a>(&'a self) -> &'a DisplayName {
        static UNKNOWN_DISPLAY_NAME: LazyLock<DisplayName> =
            LazyLock::new(|| DisplayName("Unknown".to_string()));

        self.display_name.as_ref().unwrap_or(&UNKNOWN_DISPLAY_NAME)
    }

    pub fn get_account_id<'a>(&'a self) -> &'a AccountID {
        &self.account_id
    }

    pub fn get_user_hash<'a>(&'a self) -> &'a str {
        &self.user_hash
    }
}

#[derive(Serialize, Deserialize)]
pub struct GameSession {
    session_id: GameSessionID,
    accounts: Vec<GameSessionAccount>,
}

impl GameSession {
    fn new(session_id: GameSessionID, accounts: Vec<GameSessionAccount>) -> Self {
        GameSession {
            session_id,
            accounts,
        }
    }
}

impl Into<AccountSession> for GameSession {
    fn into(self) -> AccountSession {
        AccountSession::Jagex {
            session_id: self.session_id,
            accounts: self.accounts,
        }
    }
}

pub fn fetch_game_session(id_token: &LauncherIDToken) -> GameSessionResult<GameSession> {
    let http_client = reqwest::blocking::Client::new();

    let session_request_body = serde_json::to_string(&GameSessionRequest {
        id_token: id_token.clone(),
    })?;
    let session_request = http_client
        .post(GAMESESSION_SESSION_ENDPOINT)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(session_request_body);

    let session_id_response = session_request.send()?.text().unwrap();
    let session_id: GameSessionID = serde_json::from_str(&session_id_response)?;

    let accounts_request = http_client.get(GAMESESSION_ACCOUNTS_ENDPOINT).header(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", session_id.session_id().0))?,
    );
    let accounts_response = accounts_request.send()?;
    let accounts = accounts_response.json()?;

    let game_session = GameSession::new(session_id, accounts);
    Ok(game_session)
}

#[derive(Serialize, Deserialize)]
pub enum AccountSession {
    Runescape {
        profile: RSProfileResponse,
    },
    Jagex {
        session_id: GameSessionID,
        accounts: Vec<GameSessionAccount>,
    },
}

impl XDGCredsState for AccountSession {
    const CREDS_FILENAME: &'static str = "account_session.json";
}

pub struct GameSessionClient {
    session: Option<AccountSession>,
}

impl GameSessionClient {
    pub fn new() -> GameSessionResult<Self> {
        let session = AccountSession::from_state_file()?;
        Ok(GameSessionClient { session })
    }

    pub fn set_saved_session<'a>(
        &'a mut self,
        session: AccountSession,
    ) -> GameSessionResult<&'a AccountSession> {
        session.write_state_file()?;
        self.session = Some(session);
        Ok(self.session.as_ref().unwrap())
    }

    pub fn get_session<'a>(&'a self) -> &'a Option<AccountSession> {
        &self.session
    }
}
