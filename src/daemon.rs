use std::{error::Error, fmt::Display, net::IpAddr, collections::{hash_map::RandomState, HashMap}, hash::BuildHasher, str::FromStr, process::{Child, Command}, time::{SystemTime, Duration}, io::Write, fs::{File, OpenOptions}, path::PathBuf};

use oauth2::{AuthorizationCode, ClientId, ClientSecret, TokenUrl, AuthUrl, basic::{BasicErrorResponseType, BasicTokenType}, CsrfToken, Scope, AccessToken, RefreshToken, reqwest::http_client, RequestTokenError, StandardErrorResponse, TokenResponse, ResponseType, RedirectUrl, EmptyExtraTokenFields};
use rand::{thread_rng, Rng};
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use serde::{Serialize, Deserialize};
use tiny_http::{ConfigListenAddr, Request, Method, ResponseBox, Response, Header, Server};
use url::{Url, ParseError};

use crate::{jagex_oauth::{IDToken, JagexClient, JWTParseError, TokenResponseWithJWT}, game_session::{GameSessionError, SessionID, AccountID, DisplayName, self, RSProfileResponse, GameSession, AccountSession, GameSessionClient}, LOCALHOST_V4, LOCALHOST_V6, xdg::{self, XDGDirectoryError, XDGDirectoryResult}};

const LAUNCHER_CLIENT_ID: &str = "com_jagex_auth_desktop_launcher";
const LAUNCHER_AUTH_URL: &str = "https://account.jagex.com/oauth2/auth";
const LAUNCHER_TOKEN_URL: &str = "https://account.jagex.com/oauth2/token";

const CONSENT_CLIENT_ID: &str = "1fddee4e-b100-4f4e-b2b0-097f9088f9d2";

pub const DAEMON_STATE_SUBDIR: &str = "osrs-launcher";


pub fn ensure_log_dir() -> XDGDirectoryResult<PathBuf> {
    xdg::ensure_state_home_exists(DAEMON_STATE_SUBDIR).map(|p| p.join("logs"))
}

#[derive(Debug)]
pub enum DaemonError {
    HTTPServer(Box<dyn Error + Send + Sync + 'static>),
    HTTPServerClosed,
    Request(DaemonRequestError),
    LauncherClient(LauncherClientError),
    ConsentClient(ConsentClientError),
    GameSessionClient(GameSessionError),
    OAuthParse(ParseError),
    Recv(std::io::Error),
}
pub type DaemonResult<T> = Result<T, DaemonError>;

impl Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::HTTPServer(e) => write!(f, "HTTP server error: {}", e),
            DaemonError::HTTPServerClosed => write!(f, "HTTP server was closed while listening"),
            DaemonError::Request(e) => write!(f, "{}", e),
            DaemonError::LauncherClient(e) => write!(f, "Launcher OAuth client produced an error: {}", e),
            DaemonError::ConsentClient(e) => write!(f, "Consent OAuth client produced an error: {}", e),
            DaemonError::GameSessionClient(e) => write!(f, "Game session client produced an error: {}", e),
            DaemonError::OAuthParse(e) => write!(f, "Couldn't create OAuth client: {}", e),
            DaemonError::Recv(e) => write!(f, "Couldn't receive daemon request: {}", e),
        }
    }
}

impl From<DaemonRequestError> for DaemonError {
    fn from(e: DaemonRequestError) -> Self {
        DaemonError::Request(e)
    }
}

macro_rules! trans_tuple_struct {
    ($ts:ident($m:ty)$(, $e:meta),*) => {
        $(#[$e])*
        #[repr(transparent)]
        struct $ts($m);
        impl core::ops::Deref for $ts {
            type Target = $m;

            fn deref(self: &'_ Self) -> &'_ Self::Target {
                &self.0
            }
        }
        impl From<$m> for $ts {
            fn from(arg: $m) -> Self {
                $ts(arg)
            }
        }
    };
    (pub $ts:ident($m:ty)$(, $e:meta),*) => {
        $(#[$e])*
        #[repr(transparent)]
        pub struct $ts($m);
        impl core::ops::Deref for $ts {
            type Target = $m;

            fn deref(self: &'_ Self) -> &'_ Self::Target {
                &self.0
            }
        }
        impl From<$m> for $ts {
            fn from(arg: $m) -> Self {
                $ts(arg)
            }
        }
    };
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
        .env("JX_DISPLAY_NAME", &display_name.0)
        .env("JX_SESSION_ID", &session_id.0)
        .env("JX_CHARACTER_ID", &character_id.0)
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
enum OSRSLoginProvider { Jagex, Runescape }
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
                if !deauth && daemon.launcher_client.session.tokens.is_some() {
                    return Err(DaemonRequestError::CantDeauth);
                }
                let url = daemon.launcher_client.register_auth_url()
                    .map_err(DaemonRequestError::LauncherClient)?;
                Ok(DaemonResponse::AuthorizeUrl(url))
            },
            Self::AuthorizationCode { code, state, intent } => {
                let launcher_tokens = daemon.launcher_client.authorize(code.clone(), state.clone(), intent.clone())?;
                match launcher_tokens.login_provider {
                    OSRSLoginProvider::Jagex => {
                        let consent_url = daemon.consent_client.register_auth_url()
                            .map_err(DaemonRequestError::ConsentClient)?;
                        Ok(DaemonResponse::ConsentUrl(consent_url))
                    },
                    OSRSLoginProvider::Runescape => {
                        let profile = game_session::fetch_game_profile(&launcher_tokens.id_token)?;
                        let display_name = profile.display_name.as_ref().ok_or(DaemonRequestError::RSAccountDisplayNameNotSet)?.clone();
                        daemon.g_session_client.set_saved_session(AccountSession::Runescape { profile })?;
                        Ok(DaemonResponse::CharacterList(vec![display_name]))
                    },
                }
            },
            Self::JagexJWS { code: _, id_token, state } => {
                if !daemon.consent_client.valid_state(state) {
                    return Err(DaemonRequestError::UntrackedConsentState);
                }
                let GameSession { session_id, accounts } = game_session::fetch_game_session(id_token)?;

                daemon.g_session_client.set_saved_session(AccountSession::Jagex { session_id, accounts })?;
                if let Some(AccountSession::Jagex { session_id: _, accounts }) = &daemon.g_session_client.session {
                    if accounts.len() == 1 {
                        let account = accounts.get(0).unwrap();
                        Ok(DaemonResponse::CharacterList(vec![account.display_name.0.to_string()]))
                    } else {
                        let character_names = accounts.iter().map(|a| a.display_name.0.clone() );
                        Ok(DaemonResponse::CharacterList(character_names.collect()))
                    }
                } else { unreachable!() } // surely
            },
            Self::ListCharacters => {
                match &daemon.g_session_client.session {
                    Some(AccountSession::Jagex { session_id: _, accounts }) => {
                        let character_names = accounts.iter().map(|a| a.display_name.0.clone() );
                        Ok(DaemonResponse::CharacterList(character_names.collect()))
                    },
                    Some(AccountSession::Runescape { profile }) => {
                        match &profile.display_name {
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
                params.insert("code", code.0.secret());
                params.insert("state", state.0.secret());
                params.insert("intent", intent);
            },
            DaemonRequest::JagexJWS { code, id_token, state } => {
                params.insert("code", code.secret());
                params.insert("id_token", &id_token.0.original);
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
                    .map(LauncherAuthorizationCode)?;
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
        let launcher_client = LauncherClient::new()?;
        let consent_client = ConsentClient::new()?;
        let g_session_client = GameSessionClient::new()?;
        Ok(Daemon {
            listen_address,
            launcher_client,
            consent_client,
            g_session_client,
        })
    }

    fn status(&self) -> DaemonStatus {
        match &self.g_session_client.session {
            Some(AccountSession::Jagex { session_id: _, accounts }) => 
                DaemonStatus::Launch(accounts.iter().map(|a| a.display_name.0.to_string() ).collect()),
            Some(AccountSession::Runescape { profile: RSProfileResponse { display_name: Some(display_name), .. } }) =>
                DaemonStatus::Launch(vec![display_name.to_string()]),
            Some(AccountSession::Runescape { profile: RSProfileResponse { display_name: None, .. } }) =>
                DaemonStatus::Launch(vec![]),
            None => {
                if let Some(url) = &self.consent_client.session.auth_url {
                    DaemonStatus::AwaitConsent(url.to_string())
                } else if let Some(url) = &self.launcher_client.session.auth_url {
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
        match (display_name, self.g_session_client.session.as_ref()) {
            // RuneScape account
            (None, Some(AccountSession::Runescape { profile })) => {
                let osrs_tokens = self.launcher_client.refreshed_tokens()?;
                let display_name = profile.display_name.as_ref().map(|s| s.as_str() );
                let child = run_runelite_with_rs_account(display_name, &osrs_tokens.access_token, &osrs_tokens.refresh_token)?;
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
                    Some(display_name) => match accounts.iter().find(|a| a.display_name.0.eq_ignore_ascii_case(&display_name) ) {
                        Some(a) => a,
                        None => return Err(DaemonRequestError::UnknownAccount)
                    },
                    // default to the only account if no name was specified and there is only 1 account
                    None if accounts.len() == 1 => accounts.get(0).unwrap(),
                    // if there is more than one account, a display name must be provided to select an account
                    None => return Err(DaemonRequestError::NeedDisplayNameToRun),
                };
                let child = run_runelite_with_jagex_account(&selected_account.display_name, &session_id.session_id(), &selected_account.account_id)?;
                Ok(child.id())
            },
            // Not authorized
            (_, None) => Err(DaemonRequestError::NeedAuthorizationToRun),
        }
    }
}

#[derive(Debug)]
pub enum LauncherClientError {
    NotInitialized,
    UnknownState,
    RequestToken(RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, StandardErrorResponse<BasicErrorResponseType>>),
    TokenResponseMissingIDToken,
    TokenResponseMissingRefreshToken,
    TokenResponseMissingExpiration,
    SerializeCreds(serde_json::Error),
    WriteCreds(std::io::Error),
    XDG(XDGDirectoryError),
    ReadCreds(std::io::Error),
    DeserializeCreds(serde_json::Error),
}
type LauncherClientResult<T> = Result<T, LauncherClientError>;

impl Display for LauncherClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LauncherClientError::NotInitialized => write!(f, "Launcher hasn't been initialized"),
            LauncherClientError::UnknownState => write!(f, "Unknown/untracked state"),
            LauncherClientError::RequestToken(e) => write!(f, "Couldn't exchange authorization code for launcher tokens\n{}", match e {
                RequestTokenError::ServerResponse(e) => format!("Server responded with error: {}", e),
                RequestTokenError::Request(e) => format!("Couldn't send request: {}", e),
                RequestTokenError::Parse(e, bytes) => format!("Couldn't parse server response: {}\n{}", e, String::from_utf8_lossy(bytes)),
                RequestTokenError::Other(e) => e.to_string(),
            }),
            LauncherClientError::TokenResponseMissingIDToken => write!(f, "Token exchange response was missing id_token"),
            LauncherClientError::TokenResponseMissingRefreshToken => write!(f, "Token exchange response was missing refresh_token"),
            LauncherClientError::TokenResponseMissingExpiration => write!(f, "Token exchange response was missing expires_in"),
            LauncherClientError::SerializeCreds(e) => write!(f, "Couldn't serialize credentials: {}", e),
            LauncherClientError::WriteCreds(e) => write!(f, "Couldn't save credentials: {}", e),
            LauncherClientError::XDG(e) => write!(f, "XDG environment error: {}", e),
            LauncherClientError::ReadCreds(e) => write!(f, "Couldn't read saved credentials: {}", e),
            LauncherClientError::DeserializeCreds(e) => write!(f, "Couldn't deserialize saved credentials: {}", e),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct LauncherClientSession {
    tokens: Option<LauncherTokens>,
    state: Option<LauncherClientState>,
    auth_url: Option<Url>,
}

impl LauncherClientSession {
    fn new() -> Self {
        LauncherClientSession { tokens: None, state: None, auth_url: None }
    }

    const STATE_FILENAME: &'static str = "launcher_session.json";
    pub fn ensure_state_file_path() -> LauncherClientResult<PathBuf> {
        let xdg_dir = xdg::ensure_state_home_exists(DAEMON_STATE_SUBDIR)
            .map_err(LauncherClientError::XDG)?;
        Ok(xdg_dir.join(Self::STATE_FILENAME))
    }

    pub fn set_saved_tokens<'a>(&'a mut self, tokens: LauncherTokens) -> LauncherClientResult<&'a LauncherTokens> {
        self.tokens = Some(tokens);
        self.write_state_file()?;
        Ok(self.tokens.as_ref().unwrap())
    }

    pub fn set_saved_state<'a>(&'a mut self, state: LauncherClientState) -> LauncherClientResult<&'a LauncherClientState> {
        self.state = Some(state);
        self.write_state_file()?;
        Ok(self.state.as_ref().unwrap())
    }

    pub fn set_saved_auth_url<'a>(&'a mut self, auth_url: Url) -> LauncherClientResult<&'a Url> {
        self.auth_url = Some(auth_url);
        self.write_state_file()?;
        Ok(self.auth_url.as_ref().unwrap())
    }

    pub fn from_state_file() -> LauncherClientResult<Option<Self>> {
        let creds_path = Self::ensure_state_file_path()?;
        let creds_file = match File::open(creds_path) {
            Ok(f) => f,
            Err(e) => {
                if let std::io::ErrorKind::NotFound = e.kind() {
                    return Ok(None);
                } else {
                    return Err(LauncherClientError::ReadCreds(e));
                }
            }
        };
        let creds_data: Option<Self> = serde_json::from_reader(creds_file)
            .map_err(LauncherClientError::DeserializeCreds)?;
        Ok(creds_data)
    }

    pub fn write_state_file(&self) -> LauncherClientResult<()> {
        let file_path = Self::ensure_state_file_path()?;
        let file_exists = file_path.exists();
        let mut file = OpenOptions::new()
            .create_new(!file_exists)
            .write(true)
            .open(file_path)
            .map_err(LauncherClientError::WriteCreds)?;
        let data = serde_json::to_string(&Some(&self))
            .map_err(LauncherClientError::SerializeCreds)?;
        file.write_all(data.as_bytes())
            .map_err(LauncherClientError::WriteCreds)?;
        Ok(())
    }
}

trans_tuple_struct!(pub LauncherAuthorizationCode(AuthorizationCode), derive(Clone, Debug));
trans_tuple_struct!(pub LauncherClientState(CsrfToken), derive(Clone, Debug, Serialize, Deserialize));
trans_tuple_struct!(LauncherAccessToken(AccessToken), derive(Clone, Serialize, Deserialize));
trans_tuple_struct!(pub LauncherIDToken(IDToken), derive(Clone, Debug, Serialize, Deserialize));
trans_tuple_struct!(LauncherRefreshToken(RefreshToken), derive(Clone, Serialize, Deserialize));
pub struct LauncherClient {
    oauth: JagexClient,
    session: LauncherClientSession,
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

#[derive(Serialize, Deserialize, Clone)]
pub struct LauncherTokens {
    access_token: LauncherAccessToken,
    refresh_token: LauncherRefreshToken, 
    id_token: LauncherIDToken,
    expires_at: SystemTime,
    login_provider: OSRSLoginProvider,
}

impl LauncherTokens {
    fn from_token_response(response: TokenResponseWithJWT<EmptyExtraTokenFields, BasicTokenType>) -> LauncherClientResult<Self> {
        let access_token = response.access_token();
        let id_token = response.id_token()
            .ok_or(LauncherClientError::TokenResponseMissingIDToken)?;
        let refresh_token = response.refresh_token()
            .ok_or(LauncherClientError::TokenResponseMissingRefreshToken)?;

        let mut login_provider = OSRSLoginProvider::Jagex;
        if let Some(serde_json::Value::String(s)) = id_token.claims.extra.get("login_provider") {
            if s == "runescape" {
                login_provider = OSRSLoginProvider::Runescape;
            }
        }

        let expires_at = response.expires_in().map(|d| SystemTime::now() + d )
            .ok_or(LauncherClientError::TokenResponseMissingExpiration)?;

        let tokens = LauncherTokens {
            access_token: (*access_token).clone().into(),
            refresh_token: (*refresh_token).clone().into(),
            id_token: (*id_token).clone().into(),
            expires_at, login_provider
        };
        Ok(tokens)
    }

    fn refreshed(&self, client: &JagexClient) -> LauncherClientResult<Self> {
        let request = client.exchange_refresh_token(&self.refresh_token);
        let response = request.request(http_client)
            .map_err(LauncherClientError::RequestToken)?;
        LauncherTokens::from_token_response(response)
    }

    fn expired(&self) -> bool {
        return SystemTime::now() > self.expires_at;
    }
}

impl LauncherClient {
    fn new() -> DaemonResult<Self> {
        let oauth = load_oauth_client(LAUNCHER_CLIENT_ID, None, LAUNCHER_AUTH_URL, Some(LAUNCHER_TOKEN_URL))
            .map_err(|e| DaemonError::OAuthParse(e))?;
        let session = LauncherClientSession::from_state_file()
            .map_err(DaemonError::LauncherClient)?
            .unwrap_or(LauncherClientSession::new());
        Ok(LauncherClient { oauth, session })
    }

    fn refreshed_tokens<'a>(&'a mut self) -> LauncherClientResult<&'a LauncherTokens> {
        let tokens = match self.session.tokens.as_ref() {
            Some(t) => t,
            None => return Err(LauncherClientError::NotInitialized)
        };
        let tokens = tokens.clone();
        if tokens.expired() {
            tracing::info!("refreshed expired tokens");
            self.session.set_saved_tokens(tokens.refreshed(&self.oauth)?)
        } else {
            Ok(self.session.tokens.as_ref().unwrap())
        }
    }

    fn handle_token_response<'a>(&'a mut self, response: TokenResponseWithJWT<EmptyExtraTokenFields, BasicTokenType>) -> LauncherClientResult<&'a LauncherTokens> {
        self.session.set_saved_tokens(LauncherTokens::from_token_response(response)?)
    }

    fn authorize<'a>(&'a mut self, code: LauncherAuthorizationCode, state: LauncherClientState, _intent: String) -> LauncherClientResult<&'a LauncherTokens> {
        // return error not initialized if state hasn't been set. also return error if unexpected state.
        let stored_state = self.session.state.as_ref().ok_or(LauncherClientError::NotInitialized)?;
        if stored_state.secret() != state.secret() {
            return Err(LauncherClientError::UnknownState);
        }

        let request = self.oauth.exchange_code(code.0);
        let response = request.request(http_client)
            .map_err(|e| LauncherClientError::RequestToken(e) )?;

        self.handle_token_response(response)
    }

    fn register_auth_url(&mut self) -> LauncherClientResult<String> {
        let auth_request = self.oauth.authorize_url(|| CsrfToken::new_random_len(12))
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("offline".to_string()))
            .add_scope(Scope::new("gamesso.token.create".to_string()))
            .add_scope(Scope::new("user.profile.read".to_string()));
        let (url, csrf_token) = auth_request.url();
        let url_str = url.to_string();
        self.session.set_saved_auth_url(url)?;
        self.session.set_saved_state(csrf_token.into())?;
        return Ok(url_str);
    }
}

#[derive(Debug)]
pub enum ConsentClientError {
    SerializeCreds(serde_json::Error),
    WriteCreds(std::io::Error),
    XDG(XDGDirectoryError),
    ReadCreds(std::io::Error),
    DeserializeCreds(serde_json::Error),
}
type ConsentClientResult<T> = Result<T, ConsentClientError>;

impl Display for ConsentClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsentClientError::SerializeCreds(e) => write!(f, "Couldn't serialize credentials: {}", e),
            ConsentClientError::WriteCreds(e) => write!(f, "Couldn't save credentials: {}", e),
            ConsentClientError::XDG(e) => write!(f, "XDG environment error: {}", e),
            ConsentClientError::ReadCreds(e) => write!(f, "Couldn't read saved credentials: {}", e),
            ConsentClientError::DeserializeCreds(e) => write!(f, "Couldn't deserialize saved credentials: {}", e),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ConsentClientSession {
    state: Option<ConsentState>,
    auth_url: Option<Url>,
}

impl ConsentClientSession {
    fn new() -> Self {
        ConsentClientSession { state: None, auth_url: None }
    }

    const STATE_FILENAME: &'static str = "consent_session.json";
    pub fn ensure_state_file_path() -> ConsentClientResult<PathBuf> {
        let xdg_dir = xdg::ensure_state_home_exists(DAEMON_STATE_SUBDIR)
            .map_err(ConsentClientError::XDG)?;
        Ok(xdg_dir.join(Self::STATE_FILENAME))
    }

    pub fn set_saved_state<'a>(&'a mut self, state: ConsentState) -> ConsentClientResult<&'a ConsentState> {
        self.state = Some(state);
        self.write_state_file()?;
        Ok(self.state.as_ref().unwrap())
    }

    pub fn set_saved_auth_url<'a>(&'a mut self, auth_url: Url) -> ConsentClientResult<&'a Url> {
        self.auth_url = Some(auth_url);
        self.write_state_file()?;
        Ok(self.auth_url.as_ref().unwrap())
    }

    pub fn from_state_file() -> ConsentClientResult<Option<Self>> {
        let creds_path = Self::ensure_state_file_path()?;
        let creds_file = match File::open(creds_path) {
            Ok(f) => f,
            Err(e) => {
                if let std::io::ErrorKind::NotFound = e.kind() {
                    return Ok(None);
                } else {
                    return Err(ConsentClientError::ReadCreds(e));
                }
            }
        };
        let creds_data: Option<Self> = serde_json::from_reader(creds_file)
            .map_err(ConsentClientError::DeserializeCreds)?;
        Ok(creds_data)
    }

    pub fn write_state_file(&self) -> ConsentClientResult<()> {
        let file_path = Self::ensure_state_file_path()?;
        let file_exists = file_path.exists();
        let mut file = OpenOptions::new()
            .create_new(!file_exists)
            .write(true)
            .open(file_path)
            .map_err(ConsentClientError::WriteCreds)?;
        let data = serde_json::to_string(&Some(&self))
            .map_err(ConsentClientError::SerializeCreds)?;
        file.write_all(data.as_bytes())
            .map_err(ConsentClientError::WriteCreds)?;
        Ok(())
    }
}

trans_tuple_struct!(pub ConsentState(CsrfToken), derive(Serialize, Deserialize));
pub struct ConsentClient {
    oauth: JagexClient,
    session: ConsentClientSession,
}

impl ConsentClient {
    fn new() -> DaemonResult<ConsentClient> {
        let oauth = load_oauth_client(CONSENT_CLIENT_ID, None, LAUNCHER_AUTH_URL, Some(LAUNCHER_TOKEN_URL))
            .map_err(DaemonError::OAuthParse)?;
        let session = ConsentClientSession::from_state_file()
            .map_err(DaemonError::ConsentClient)?
            .unwrap_or(ConsentClientSession::new());
        Ok(ConsentClient { oauth, session })
    }

    fn register_auth_url(&mut self) -> ConsentClientResult<String> {
        let nonce: String = thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        let (url, token) = self.oauth.authorize_url(CsrfToken::new_random)
            .use_implicit_flow()
            .set_response_type(&ResponseType::new("id_token code".to_string()))
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("offline".to_string()))
            .add_extra_param("nonce", nonce)
            .set_redirect_uri(std::borrow::Cow::Owned(RedirectUrl::new("http://localhost".to_string()).unwrap()))
            .url();
        let url_str = self.session.set_saved_auth_url(url)?.clone().into();
        self.session.set_saved_state(token.into())?;
        return Ok(url_str);
    }

    fn valid_state(&self, s: &str) -> bool {
        self.session.state.as_ref().is_some_and(|cs| cs.secret() == s )
    }
}
