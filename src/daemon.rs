use std::{error::Error, fmt::Display, net::{IpAddr, Ipv6Addr, Ipv4Addr}, collections::{hash_map::RandomState, HashMap}, hash::BuildHasher, str::FromStr, process::{Child, Command}, time::Duration, path::PathBuf};

use oauth2::{AuthorizationCode, ClientId, ClientSecret, TokenUrl, AuthUrl, CsrfToken, AccessToken, RefreshToken};
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use serde::{Serialize, Deserialize};
use tiny_http::{ConfigListenAddr, Request, Method, ResponseBox, Response, Header, Server};
use url::{Url, ParseError};

pub mod launcher_client;
pub mod game_session;
pub mod consent_client;
mod jagex_oauth;
mod common;

use crate::{xdg::{XDGDirectoryResult, self}, trans_tuple_struct};

use self::{jagex_oauth::{IDToken, JagexClient, JWTParseError}, game_session::{GameSessionError, SessionID, AccountID, DisplayName, RSProfileResponse, AccountSession, GameSessionClient}, launcher_client::{LauncherClientError, LauncherAuthorizationCode, LauncherClientState, LauncherIDToken, LauncherClient}, consent_client::{ConsentClientError, ConsentClient}};

pub const DAEMON_STATE_SUBDIR: &str = "osrs-launcher";

const LOCALHOST_V4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const LOCALHOST_V6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

pub fn ensure_log_dir() -> XDGDirectoryResult<PathBuf> {
    xdg::ensure_state_home_exists(DAEMON_STATE_SUBDIR).map(|p| p.join("logs"))
}

fn load_oauth_client(client_id: &str, client_secret: Option<&str>, auth_url: &str, token_url: Option<&str>) -> Result<JagexClient, ParseError> {
    let client_id = ClientId::new(client_id.to_string());
    let client_secret = client_secret.and_then(|cs| Some(ClientSecret::new(cs.to_string())));
    let auth_url = AuthUrl::new(auth_url.to_string())?;
    let token_url = match token_url {
        Some(url) => Some(TokenUrl::new(url.to_string())?),
        None => None
    };
    let client = JagexClient::new(client_id, client_secret, auth_url, token_url);
    Ok(client)
}

#[derive(Debug)]
pub enum DaemonError {
    HTTPServer(Box<dyn Error + Send + Sync + 'static>),
    HTTPServerClosed,
    Recv(std::io::Error),
    Request(DaemonRequestError),
    LauncherClient(LauncherClientError),
    ConsentClient(ConsentClientError),
    GameSessionClient(GameSessionError),
}
pub type DaemonResult<T> = Result<T, DaemonError>;

impl Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::HTTPServer(e) => write!(f, "HTTP server error: {}", e),
            DaemonError::HTTPServerClosed => write!(f, "HTTP server was closed while listening"),
            DaemonError::Recv(e) => write!(f, "Couldn't receive daemon request: {}", e),
            DaemonError::Request(e) => write!(f, "{}", e),
            DaemonError::LauncherClient(e) => write!(f, "Launcher OAuth client produced an error: {}", e),
            DaemonError::ConsentClient(e) => write!(f, "Consent OAuth client produced an error: {}", e),
            DaemonError::GameSessionClient(e) => write!(f, "Game session client produced an error: {}", e),
        }
    }
}

impl From<DaemonRequestError> for DaemonError {
    fn from(e: DaemonRequestError) -> Self {
        DaemonError::Request(e)
    }
}

trans_tuple_struct!(DaemonSessionID(String));

#[derive(Serialize, Deserialize, Debug)]
pub enum DaemonResponse {
    Launched(u32),
    ReadyToLaunch,
    NotAuthenticated,
    AlreadyAuthorized,
    AuthorizeUrl(String),
    ConsentUrl(String),
    CharacterList(Vec<String>),
    UnknownCharacter(String),
    RawHtml(String),
    Status(DaemonStatus, u32), // DaemonStatus, pid
    ErrorStr(String),
}

impl TryInto<ResponseBox> for DaemonResponse {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<ResponseBox, serde_json::Error> {
        match self {
            DaemonResponse::RawHtml(s) => {
                let header = Header::from_bytes("content-type", "text/html").unwrap(); // this will *not* panic :)
                Ok(Response::from_string(s).with_header(header).boxed())
            },
            DaemonResponse::ErrorStr(_) => Ok(Response::from_string(serde_json::to_string(&self)?).with_status_code(500).boxed()),
            response => Ok(Response::from_string(serde_json::to_string(&response)?).boxed()),
        }
    }
}

impl From<DaemonRequestError> for DaemonResponse {
    fn from(e: DaemonRequestError) -> Self {
        DaemonResponse::ErrorStr(format!("{}", e))
    }
}

#[derive(Debug)]
pub enum DaemonRequest {
    Launch { display_name: Option<String> },
    ForwardJS,
    AuthorizationURLRequest{ deauth: bool },
    AuthorizationCode{ code: LauncherAuthorizationCode, state: LauncherClientState, intent: String },
    JagexJWS{ code: AuthorizationCode, id_token: LauncherIDToken, state: String  },
    ListCharacters,
    Status,
}

#[derive(Debug)]
pub enum DaemonRequestError {
    URLParse(ParseError),
    UnknownPath(String),
    IO(std::io::Error),
    MissingParam(&'static str),
    JWTParse(JWTParseError),
    SerializeResponse(serde_json::Error),
    LauncherClient(LauncherClientError),
    ConsentClient(ConsentClientError),
    GameSession(GameSessionError),
    SetRSAccountDisplayName,
    NeedAuthorizationToRun,
    UnknownAccount,
    CantDeauth,
    UntrackedConsentState,
    NeedDisplayNameToRun,
    RSAccountDisplayNameNotSet,
    NoCharacters,
}
type DaemonRequestResult<T> = Result<T, DaemonRequestError>;

macro_rules! from_error_wrapper {
    ($src_error:ty, $dest_error:ty, $dest_variant:path) => {
        impl From<$src_error> for $dest_error {
            fn from(e: $src_error) -> Self {
                $dest_variant(e)
            }
        }
    };
}

from_error_wrapper!(std::io::Error, DaemonRequestError, DaemonRequestError::IO);
from_error_wrapper!(LauncherClientError, DaemonRequestError, DaemonRequestError::LauncherClient);
from_error_wrapper!(GameSessionError, DaemonRequestError, DaemonRequestError::GameSession);

impl Display for DaemonRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::URLParse(e) => write!(f, "URL parse error - {}", e),
            Self::UnknownPath(e) => write!(f, "Unknown request path \"{}\"", e),
            Self::IO(e) => write!(f, "IO error: {}", e),
            Self::MissingParam(e) => write!(f, "Missing required parameter: {}", e),
            Self::JWTParse(e) => write!(f, "Couldn't parse JWT/id_token - {}", e),
            Self::SerializeResponse(e) => write!(f, "Couldn't serialize response - {}", e),
            Self::LauncherClient(e) => write!(f, "Launcher OAuth client error - {}", e),
            Self::ConsentClient(e) => write!(f, "Consent OAuth client error - {}", e),
            Self::GameSession(e) => write!(f, "Game session client error - {}", e),
            Self::SetRSAccountDisplayName => write!(f, "Couldn't select a character by display name on a non-jagex account"),
            Self::NeedAuthorizationToRun => write!(f, "Couldnt run client without completing the authorization flow"),
            Self::UnknownAccount => write!(f, "Couldn't select account by display name - unknown display name"),
            Self::CantDeauth => write!(f, "Couldn't restart authorization flow - set param deauth=1 to force restart"),
            Self::UntrackedConsentState => write!(f, "Unknown/untracked consent client state"),
            Self::NeedDisplayNameToRun => write!(f, "Couldn't assume character to launch as - please specify display name"),
            Self::RSAccountDisplayNameNotSet => write!(f, "Couldn't read display name of Runescape account with no display name set"),
            Self::NoCharacters => write!(f, "Couldn't launch account with no characters"),
        }
    }
}

fn parse_params<H: BuildHasher + Default, T: std::io::Read>(reader: &mut T) -> Result<HashMap<String, String, H>, DaemonRequestError> {
    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    let params = form_urlencoded::parse(&body)
        .map(|(key, value)| (key.to_string(), value.to_string()) );
    Ok(params.collect::<HashMap<String, String, H>>())
}

fn run_runelite_with_rs_account(display_name: Option<&str>, access_token: &AccessToken, refresh_token: &RefreshToken) -> Result<Child, std::io::Error> {
    return Ok(Command::new("runelite")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env("JX_DISPLAY_NAME", display_name.unwrap_or(""))
        .env("JX_ACCESS_TOKEN", access_token.secret())
        .env("JX_REFRESH_TOKEN", refresh_token.secret())
        .spawn()?);
}

fn run_runelite_with_jagex_account(display_name: &DisplayName, session_id: &SessionID, character_id: &AccountID) -> Result<Child, std::io::Error> {
    return Ok(Command::new("runelite")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env("JX_DISPLAY_NAME", display_name.as_ref())
        .env("JX_SESSION_ID", session_id.as_ref())
        .env("JX_CHARACTER_ID", character_id.as_ref())
        .spawn()?);
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum DaemonStatus {
    NeedAuthorization,
    Launch(Vec<String>),
    AwaitAuthorization(String),
    AwaitConsent(String),
}

#[derive(Serialize, Deserialize, Clone)]
pub enum OSRSLoginProvider { Jagex, Runescape }
impl DaemonRequest {
    const FORWARD_JS_CONTENT: &'static str = include_str!("forwarder.html");

    fn run(&self, daemon: &mut Daemon) -> DaemonRequestResult<DaemonResponse> {
        match self {
            Self::Launch { display_name } => {
                let rl_pid = daemon.spawn_requested_rl_instance(display_name.as_ref().map(|dn| dn.as_str() ))?;
                Ok(DaemonResponse::Launched(rl_pid))
            },
            Self::ForwardJS => Ok(DaemonResponse::RawHtml(Self::FORWARD_JS_CONTENT.to_string())),
            Self::AuthorizationURLRequest { deauth } => {
                if !deauth && daemon.launcher_client.get_session().get_tokens().is_some() {
                    return Err(DaemonRequestError::CantDeauth);
                }
                let url = daemon.launcher_client.register_auth_url()
                    .map_err(DaemonRequestError::LauncherClient)?;
                Ok(DaemonResponse::AuthorizeUrl(url))
            },
            Self::AuthorizationCode { code, state, intent } => {
                let launcher_tokens = daemon.launcher_client.authorize(code.clone(), state.clone(), intent.clone())?;
                match launcher_tokens.get_login_provider() {
                    OSRSLoginProvider::Jagex => {
                        let consent_url = daemon.consent_client.register_auth_url()
                            .map_err(DaemonRequestError::ConsentClient)?;
                        Ok(DaemonResponse::ConsentUrl(consent_url))
                    },
                    OSRSLoginProvider::Runescape => {
                        let profile = game_session::fetch_game_profile(launcher_tokens.get_id_token())?;
                        let display_name = profile.get_display_name().clone().ok_or(DaemonRequestError::RSAccountDisplayNameNotSet)?;
                        daemon.g_session_client.set_saved_session(AccountSession::Runescape { profile })?;
                        Ok(DaemonResponse::CharacterList(vec![display_name]))
                    },
                }
            },
            Self::JagexJWS { code: _, id_token, state } => {
                if !daemon.consent_client.valid_state(state) {
                    return Err(DaemonRequestError::UntrackedConsentState);
                }
                let game_session = game_session::fetch_game_session(id_token)?;

                daemon.g_session_client.set_saved_session(game_session.into())?;
                if let Some(AccountSession::Jagex { session_id: _, accounts }) = &daemon.g_session_client.get_session() {
                    if accounts.len() == 1 {
                        let account = accounts.get(0).unwrap();
                        Ok(DaemonResponse::CharacterList(vec![account.get_display_name().to_string()]))
                    } else {
                        let character_names = accounts.iter().map(|a| a.get_display_name().to_string() );
                        Ok(DaemonResponse::CharacterList(character_names.collect()))
                    }
                } else { unreachable!() } // surely
            },
            Self::ListCharacters => {
                match &daemon.g_session_client.get_session() {
                    Some(AccountSession::Jagex { session_id: _, accounts }) => {
                        let character_names = accounts.iter().map(|a| a.get_display_name().to_string() );
                        Ok(DaemonResponse::CharacterList(character_names.collect()))
                    },
                    Some(AccountSession::Runescape { profile }) => {
                        match profile.get_display_name() {
                            Some(dn) => Ok(DaemonResponse::CharacterList(vec![dn.to_string()])),
                            None => Err(DaemonRequestError::RSAccountDisplayNameNotSet)
                        }
                    },
                    None => Err(DaemonRequestError::NeedAuthorizationToRun),
                }
            },
            Self::Status => {
                Ok(DaemonResponse::Status(daemon.status(), std::process::id()))
            }
        }
    }

    fn http_method(&self) -> tiny_http::Method {
        match self {
            DaemonRequest::Launch { display_name: _ } => Method::Post,
            DaemonRequest::ForwardJS => Method::Get,
            DaemonRequest::AuthorizationURLRequest { deauth: _ } => Method::Post,
            DaemonRequest::AuthorizationCode { code: _, state: _, intent: _ } => Method::Post,
            DaemonRequest::JagexJWS { code: _, id_token: _, state: _ } => Method::Post,
            DaemonRequest::ListCharacters => Method::Get,
            DaemonRequest::Status => Method::Get,
        }
    }

    fn http_path(&self) -> &'static str {
        match self {
            DaemonRequest::Launch { display_name: _ } => "/launch",
            DaemonRequest::ForwardJS => "/",
            DaemonRequest::AuthorizationURLRequest { deauth: _ } => "/authorize",
            DaemonRequest::AuthorizationCode { code: _, state: _, intent: _ } => "/authcode",
            DaemonRequest::JagexJWS { code: _, id_token: _, state: _ } => "/jws",
            DaemonRequest::ListCharacters => "/characters",
            DaemonRequest::Status => "/status",
        }
    }

    fn http_post_body(&self) -> Option<String> {
        let mut params: HashMap<&str, &str> = HashMap::new();
        match self {
            DaemonRequest::Launch { display_name } => {
                if let Some(name) = display_name {
                    params.insert("display_name", name);
                }
            },
            DaemonRequest::AuthorizationURLRequest { deauth } => {
                params.insert("deauth", match deauth { true => "1", false => "0" });
            },
            DaemonRequest::AuthorizationCode { code, state, intent } => {
                params.insert("code", code.as_ref().secret());
                params.insert("state", state.as_ref().secret());
                params.insert("intent", intent);
            },
            DaemonRequest::JagexJWS { code, id_token, state } => {
                params.insert("code", code.secret());
                params.insert("id_token", &id_token.as_ref().original);
                params.insert("state", state);
            },
            DaemonRequest::ListCharacters | DaemonRequest::ForwardJS | DaemonRequest::Status => return None,
        };
        let encoded = params.into_iter()
            .map(|(key, value)| {
                let value_encoded: String = url::form_urlencoded::byte_serialize(value.as_bytes())
                    .collect();
                [key, "=", value_encoded.as_str()].concat()
            }).collect::<Vec<String>>().join("&");
        Some(encoded)
    }
    
    fn from_tiny_http_request(request: &mut tiny_http::Request) -> Result<Self, DaemonRequestError> {
        let localhost_url = Url::parse("http://localhost").unwrap();
        let request_url = localhost_url.join(request.url())
            .map_err(|e| DaemonRequestError::URLParse(e) )?;
        match (request.method(), request_url.path()) {
            (Method::Get, "/") => Ok(Self::ForwardJS),
            (Method::Post, "/launch") => {
                let params: HashMap<_, _, RandomState> = parse_params(&mut request.as_reader())?;
                let display_name = params.get("display_name").map(String::to_string);
                Ok(Self::Launch { display_name })
            },
            (Method::Post, "/authorize") => {
                let params: HashMap<_, _, RandomState> = parse_params(&mut request.as_reader())?;
                // deauth is only true if there is a params with the value "1"
                let deauth = match params.get("deauth") {
                    Some(v) => *v == "1",
                    None => false,
                };
                Ok(Self::AuthorizationURLRequest { deauth: deauth })
            },
            (Method::Post, "/authcode") => {
                let params: HashMap<_, _, RandomState> = parse_params(&mut request.as_reader())?;
                let code = params.get("code").ok_or(DaemonRequestError::MissingParam("code"))
                    .map(|c| AuthorizationCode::new(c.to_string()) )
                    .map(LauncherAuthorizationCode::from)?;
                let state = params.get("state").ok_or(DaemonRequestError::MissingParam("state"))
                    .map(|s| CsrfToken::new(s.to_string()) )
                    .map(LauncherClientState::from)?;
                let intent = params.get("intent").ok_or(DaemonRequestError::MissingParam("intent"))?.to_string();
                Ok(Self::AuthorizationCode { code, state, intent })
            },
            (Method::Post, "/jws") => {
                let params: HashMap<_, _, RandomState> = parse_params(&mut request.as_reader())?;
                let code = params.get("code").ok_or(DaemonRequestError::MissingParam("code"))
                    .map(|c| AuthorizationCode::new(c.to_string()) )?;
                let id_token = params.get("id_token").ok_or(DaemonRequestError::MissingParam("id_token"))
                    .map(|c| IDToken::from_str(c) )?
                    .map(|idt| LauncherIDToken::from(idt) )
                    .map_err(|e| DaemonRequestError::JWTParse(e) )?;
                let state = params.get("state").ok_or(DaemonRequestError::MissingParam("state"))?.to_string();
                Ok(Self::JagexJWS { code, id_token, state })
            },
            (Method::Get, "/characters") => Ok(Self::ListCharacters),
            (Method::Get, "/status") => Ok(Self::Status),
            (_, elsestr) => Err(DaemonRequestError::UnknownPath(elsestr.to_string())),
        }
    }

    pub fn to_reqwest_request(&self, url_base: &str, client: &reqwest::blocking::Client) -> Result<reqwest::blocking::Request, reqwest::Error> {
        let full_http_path = [url_base, self.http_path()].concat();
        let mut builder = match self.http_method() {
            Method::Get => client.get(full_http_path),
            Method::Post => client.post(full_http_path),
            _ => unreachable!(), // surely
        };
        if let Some(post_body) = self.http_post_body() {
            builder = builder
                .header(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"))
                .body(post_body);
        }
        builder.build()
    }
}

fn is_request_local(request: &Request) -> bool {
    match request.remote_addr() {
        Some(a) => match a.ip() {
            IpAddr::V4(ip) => ip == LOCALHOST_V4,
            IpAddr::V6(ip) => ip == LOCALHOST_V6
        },
        None => false
    }
}

fn display_error_response<TS: Display>(ts: TS) -> ResponseBox {
    Response::from_string(ts.to_string())
        .with_status_code(500).boxed()
}

pub struct Daemon {
    listen_address: ConfigListenAddr,
    launcher_client: LauncherClient,
    consent_client: ConsentClient,
    g_session_client: GameSessionClient,
}

impl Daemon {
    pub fn new(listen_address: ConfigListenAddr) -> DaemonResult<Self> {
        let launcher_client = LauncherClient::new()
            .map_err(DaemonError::LauncherClient)?;
        let consent_client = ConsentClient::new()
            .map_err(DaemonError::ConsentClient)?;
        let g_session_client = GameSessionClient::new()
            .map_err(DaemonError::GameSessionClient)?;
        Ok(Daemon {
            listen_address,
            launcher_client,
            consent_client,
            g_session_client,
        })
    }

    fn status(&self) -> DaemonStatus {
        match &self.g_session_client.get_session() {
            Some(AccountSession::Jagex { accounts, .. }) => 
                DaemonStatus::Launch(accounts.iter().map(|a| a.get_display_name().to_string() ).collect()),
            Some(AccountSession::Runescape { profile: RSProfileResponse { display_name: Some(display_name), .. } }) =>
                DaemonStatus::Launch(vec![display_name.to_string()]),
            Some(AccountSession::Runescape { profile: RSProfileResponse { display_name: None, .. } }) =>
                DaemonStatus::Launch(vec![]),
            None => {
                if let Some(url) = &self.consent_client.get_session().get_auth_url() {
                    DaemonStatus::AwaitConsent(url.to_string())
                } else if let Some(url) = &self.launcher_client.get_session().get_auth_url() {
                    DaemonStatus::AwaitAuthorization(url.to_string())
                } else {
                    DaemonStatus::NeedAuthorization
                }
            },
        }
    }

    fn handle_queued_requests(&mut self, http_server: &Server) -> DaemonResult<()> {
        loop {
            match http_server.try_recv() {
                Ok(Some(request)) => if is_request_local(&request) { self.handle_request(request)? },
                Err(e) => return Err(DaemonError::Recv(e)), // Server closed, etc.
                Ok(None) => break Ok(()), // None left in queue
            };
        }
    }

    const LOOP_DELAY_MS: u64 = 100;
    pub fn run(&mut self) -> DaemonResult<()> {
        let server_config = tiny_http::ServerConfig {
            addr: self.listen_address.clone(),
            ssl: None,
        };
        // start listening
        let http_server = tiny_http::Server::new(server_config)
            .map_err(|e| DaemonError::HTTPServer(e) )?;
        loop {
            // exhaust request queue
            self.handle_queued_requests(&http_server)?;
            self.check_and_refresh_tokens()?;
            std::thread::sleep(Duration::from_millis(Daemon::LOOP_DELAY_MS));
        }
    }

    fn check_and_refresh_tokens(&mut self) -> DaemonResult<()> {
        match self.launcher_client.refreshed_tokens() {
            Ok(_) => (), // refreshed successfully or did nothing
            Err(LauncherClientError::NotInitialized) => (), // not initialized, didn't need to refresh
            Err(e) => return Err(DaemonError::Request(DaemonRequestError::LauncherClient(e)))
        }
        Ok(())
    }

    fn handle_request(&mut self, mut request: Request) -> DaemonRequestResult<()> {
        let daemon_request = match DaemonRequest::from_tiny_http_request(&mut request) {
            Ok(req) => req,
            Err(e) => {
                tracing::warn!("Error reading request: {}", e);
                return Ok(request.respond(display_error_response(e))?)
            }
        };
        let daemon_response = daemon_request.run(self)
            .unwrap_or_else(|e| DaemonResponse::ErrorStr(e.to_string()) );
        let response: ResponseBox = daemon_response.try_into()
            .map_err(|e| DaemonRequestError::SerializeResponse(e) )?;
        request.respond(response).map_err(|e| DaemonRequestError::IO(e) )
    }

    fn spawn_requested_rl_instance(&mut self, display_name: Option<&str>) -> DaemonRequestResult<u32> {
        match (display_name, self.g_session_client.get_session()) {
            // RuneScape account
            (None, Some(AccountSession::Runescape { profile })) => {
                let osrs_tokens = self.launcher_client.refreshed_tokens()?;
                let display_name = profile.get_display_name().as_ref().map(|s| s.as_str() );
                let child = run_runelite_with_rs_account(display_name, osrs_tokens.get_access_token(), osrs_tokens.get_refresh_token())?;
                Ok(child.id())
            },
            (Some(_), Some(AccountSession::Runescape { .. })) => Err(DaemonRequestError::SetRSAccountDisplayName),
            // Jagex account
            (display_name_opt, Some(AccountSession::Jagex { session_id, accounts })) => {
                if accounts.len() == 0 {
                    return Err(DaemonRequestError::NoCharacters);
                }
                let selected_account = match display_name_opt {
                    // if the display name was specified, find it in the list and error if not found
                    Some(display_name) => match accounts.iter().find(|a| a.get_display_name().eq_ignore_ascii_case(&display_name) ) {
                        Some(a) => a,
                        None => return Err(DaemonRequestError::UnknownAccount)
                    },
                    // default to the only account if no name was specified and there is only 1 account
                    None if accounts.len() == 1 => accounts.get(0).unwrap(),
                    // if there is more than one account, a display name must be provided to select an account
                    None => return Err(DaemonRequestError::NeedDisplayNameToRun),
                };
                let child = run_runelite_with_jagex_account(selected_account.get_display_name(), &session_id.session_id(), &selected_account.get_account_id())?;
                Ok(child.id())
            },
            // Not authorized
            (_, None) => Err(DaemonRequestError::NeedAuthorizationToRun),
        }
    }
}