use std::{error::Error, fmt::Display, net::IpAddr, collections::{hash_map::RandomState, HashMap}, hash::BuildHasher, str::FromStr, process::{Child, Command}};

use oauth2::{AuthorizationCode, ClientId, ClientSecret, TokenUrl, AuthUrl, basic::BasicErrorResponseType, CsrfToken, Scope, AccessToken, RefreshToken, reqwest::http_client, RequestTokenError, StandardErrorResponse, TokenResponse, ResponseType, RedirectUrl};
use rand::{thread_rng, Rng};
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use serde::{Serialize, Deserialize};
use tiny_http::{ConfigListenAddr, Request, Method, ResponseBox, Response, Header};
use url::{Url, ParseError};

use crate::{jagex_oauth::{IDToken, JagexClient, JWTParseError}, game_session::{GameSessionError, SessionID, AccountID, DisplayName, self, RSProfileResponse}, LOCALHOST_V4, LOCALHOST_V6};

const LAUNCHER_CLIENT_ID: &str = "com_jagex_auth_desktop_launcher";
const LAUNCHER_AUTH_URL: &str = "https://account.jagex.com/oauth2/auth";
const LAUNCHER_TOKEN_URL: &str = "https://account.jagex.com/oauth2/token";

const OSRS_CLIENT_ID: &str = "com_jagex_auth_desktop_osrs";
const OSRS_CLIENT_SECRET: &str = "public";
const OSRS_AUTH_URL: &str = "https://auth.jagex.com/shield/oauth/auth";
const OSRS_TOKEN_URL: &str = "https://auth.jagex.com/shield/oauth/token";

const CONSENT_CLIENT_ID: &str = "1fddee4e-b100-4f4e-b2b0-097f9088f9d2";

#[derive(Debug)]
pub enum DaemonError {
    OSRSClient(OSRSClientError),
    HTTPServer(Box<dyn Error + Send + Sync + 'static>),
    HTTPServerClosed,
    Request(DaemonRequestError),
    OAuthParse(ParseError),
}
pub type DaemonResult<T> = Result<T, DaemonError>;

impl Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::OSRSClient(e) => write!(f, "[OSRS Client] {}", e),
            DaemonError::HTTPServer(e) => write!(f, "HTTP server error: {}", e),
            DaemonError::HTTPServerClosed => write!(f, "HTTP server was closed while listening"),
            DaemonError::Request(e) => write!(f, "{}", e),
            DaemonError::OAuthParse(e) => write!(f, "Couldn't create OAuth client: {}", e),
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

pub enum AccountSession {
    Runescape { profile: RSProfileResponse },
    Jagex { session_id: game_session::SessionID, accounts: Vec<game_session::GameSessionAccount> },
}

trans_tuple_struct!(DaemonSessionID(String));
pub struct Daemon {
    listen_address: ConfigListenAddr,
    launcher_client: LauncherClient,
    osrs_client: OSRSClient,
    consent_client: ConsentClient,
    account_session: Option<AccountSession>,
}

#[derive(Serialize, Deserialize)]
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

pub enum DaemonRequestType {
    Launch { display_name: Option<String> },
    ForwardJS,
    AuthorizationURLRequest{ deauth: bool },
    AuthorizationCode{ code: LauncherAuthorizationCode, state: LauncherClientState, intent: String },
    JagexJWS{ code: AuthorizationCode, id_token: LauncherIDToken, state: String  },
    ListCharacters,
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
    OSRSClient(OSRSClientError),
    GameSession(GameSessionError),
    SetRSAccountDisplayName,
    NeedAuthorizationToRun,
    UnknownAccount,
    CantDeauth,
    UntrackedConsentState,
    NeedDisplayNameToRun,
    RSAccountDisplayNameNotSet,
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
from_error_wrapper!(OSRSClientError, DaemonRequestError, DaemonRequestError::OSRSClient);
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
            Self::OSRSClient(e) => write!(f, "OSRS OAuth client error - {}", e),
            Self::GameSession(e) => write!(f, "Game session client error - {}", e),
            Self::SetRSAccountDisplayName => write!(f, "Couldn't select a character by display name on a non-jagex account"),
            Self::NeedAuthorizationToRun => write!(f, "Couldnt run client without completing the authorization flow"),
            Self::UnknownAccount => write!(f, "Couldn't select account by display name - unknown display name"),
            Self::CantDeauth => write!(f, "Couldn't restart authorization flow - set param deauth=1 to force restart"),
            Self::UntrackedConsentState => write!(f, "Unknown/untracked consent client state"),
            Self::NeedDisplayNameToRun => write!(f, "Couldn't assume character to launch as - please specify display name"),
            Self::RSAccountDisplayNameNotSet => write!(f, "Couldn't read display name of Runescape account with no display name set"),
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

#[derive(Clone)]
enum OSRSLoginProvider { Jagex, Runescape }
impl DaemonRequestType {
    const FORWARD_JS_CONTENT: &'static str = include_str!("forwarder.html");

    fn run(&self, daemon: &mut Daemon) -> DaemonRequestResult<DaemonResponse> {
        match self {
            Self::Launch { display_name: Some(display_name) } => {
                let (session_id, accounts) = match &daemon.account_session {
                    Some(AccountSession::Runescape { profile: _ }) => return Err(DaemonRequestError::SetRSAccountDisplayName),
                    None => return Err(DaemonRequestError::NeedAuthorizationToRun),
                    Some(AccountSession::Jagex { session_id, accounts }) => (session_id, accounts),
                };
                 
                let selected_account = match accounts.iter().find(|a| a.display_name.0.eq_ignore_ascii_case(&display_name) ) {
                    Some(a) => a,
                    None => return Err(DaemonRequestError::UnknownAccount),
                };
                let child = run_runelite_with_jagex_account(&selected_account.display_name, &session_id, &selected_account.account_id)?;
                Ok(DaemonResponse::Launched(child.id()))
            },
            Self::Launch { display_name: None } => {
                match &daemon.account_session {
                    Some(AccountSession::Jagex { session_id, accounts }) => {
                        if accounts.len() == 1 {
                            let account = accounts.get(0).unwrap();
                            let child = run_runelite_with_jagex_account(&account.display_name, &session_id, &account.account_id)?;
                            Ok(DaemonResponse::Launched(child.id()))
                        } else {
                            Err(DaemonRequestError::NeedDisplayNameToRun)
                        }
                    },
                    Some(AccountSession::Runescape { profile }) => {
                        let osrs_tokens = daemon.launcher_client.tokens()?;
                        let display_name = profile.display_name.as_ref().ok_or(DaemonRequestError::RSAccountDisplayNameNotSet)?;
                        let child = run_runelite_with_rs_account(Some(display_name.as_str()), &osrs_tokens.0, &osrs_tokens.1)?;
                        Ok(DaemonResponse::Launched(child.id()))
                    },
                    None => Err(DaemonRequestError::NeedAuthorizationToRun),
                }
            },
            Self::ForwardJS => Ok(DaemonResponse::RawHtml(Self::FORWARD_JS_CONTENT.to_string())),
            Self::AuthorizationURLRequest { deauth } => {
                if !deauth && daemon.launcher_client.tokens().is_ok() {
                    return Err(DaemonRequestError::CantDeauth);
                }
                let url = daemon.launcher_client.register_auth_url();
                Ok(DaemonResponse::AuthorizeUrl(url))
            },
            Self::AuthorizationCode { code, state, intent } => {
                let (access_token, id_token) = daemon.launcher_client.authorize(code.clone(), state.clone(), intent.clone())
                    .map(|(at, it, _)| (at.clone(), it.clone()))?;
                match daemon.launcher_client.login_provider {
                    Some(OSRSLoginProvider::Jagex) => Ok(DaemonResponse::ConsentUrl(daemon.consent_client.register_auth_url())),
                    Some(OSRSLoginProvider::Runescape) => {
                        let osrs_tokens = daemon.osrs_client.exchange_jagex_client_access_token(&access_token)?;
                        let profile = game_session::fetch_game_profile(&id_token)?;
                        let display_name = profile.display_name.as_ref().ok_or(DaemonRequestError::RSAccountDisplayNameNotSet)?.clone();
                        daemon.account_session = Some(AccountSession::Runescape { profile });
                        let child = run_runelite_with_rs_account(Some(display_name.as_str()), &osrs_tokens.0, &osrs_tokens.1)?;
                        return Ok(DaemonResponse::Launched(child.id()));
                    },
                    None => todo!()
                }
            },
            Self::JagexJWS { code: _, id_token, state } => {
                if !daemon.consent_client.valid_state(state) {
                    return Err(DaemonRequestError::UntrackedConsentState);
                }
                let (sess_id, accounts) = game_session::fetch_game_session(id_token)?;

                daemon.account_session = Some(AccountSession::Jagex { session_id: sess_id, accounts });
                if let Some(AccountSession::Jagex { session_id, accounts }) = &daemon.account_session {
                    if accounts.len() == 1 {
                        let account = accounts.get(0).unwrap();
                        let child = run_runelite_with_jagex_account(&account.display_name, &session_id, &account.account_id)?;
                        Ok(DaemonResponse::Launched(child.id()))
                    } else {
                        let character_names = accounts.iter().map(|a| a.display_name.0.clone() );
                        Ok(DaemonResponse::CharacterList(character_names.collect()))
                    }
                } else { unreachable!() } // surely
            },
            Self::ListCharacters => {
                match &daemon.account_session {
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
        }
    }

    fn http_method(&self) -> tiny_http::Method {
        match self {
            DaemonRequestType::Launch { display_name: _ } => Method::Post,
            DaemonRequestType::ForwardJS => Method::Get,
            DaemonRequestType::AuthorizationURLRequest { deauth: _ } => Method::Post,
            DaemonRequestType::AuthorizationCode { code: _, state: _, intent: _ } => Method::Post,
            DaemonRequestType::JagexJWS { code: _, id_token: _, state: _ } => Method::Post,
            DaemonRequestType::ListCharacters => Method::Get,
        }
    }

    fn http_path(&self) -> &'static str {
        match self {
            DaemonRequestType::Launch { display_name: _ } => "/launch",
            DaemonRequestType::ForwardJS => "/",
            DaemonRequestType::AuthorizationURLRequest { deauth: _ } => "/authorize",
            DaemonRequestType::AuthorizationCode { code: _, state: _, intent: _ } => "/authcode",
            DaemonRequestType::JagexJWS { code: _, id_token: _, state: _ } => "/jws",
            DaemonRequestType::ListCharacters => "/characters",
        }
    }

    fn http_post_body(&self) -> Option<String> {
        let mut params: HashMap<&str, &str> = HashMap::new();
        match self {
            DaemonRequestType::Launch { display_name } => {
                if let Some(name) = display_name {
                    params.insert("display_name", name);
                }
            },
            DaemonRequestType::AuthorizationURLRequest { deauth } => {
                params.insert("deauth", match deauth { true => "1", false => "0" });
            },
            DaemonRequestType::AuthorizationCode { code, state, intent } => {
                params.insert("code", code.0.secret());
                params.insert("state", state.0.secret());
                params.insert("intent", intent);
            },
            DaemonRequestType::JagexJWS { code, id_token, state } => {
                params.insert("code", code.secret());
                params.insert("id_token", &id_token.0.original);
                params.insert("state", state);
            },
            DaemonRequestType::ListCharacters | DaemonRequestType::ForwardJS => return None,
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

impl Daemon {
    pub fn new(listen_address: ConfigListenAddr) -> DaemonResult<Self> {
        let launcher_client = LauncherClient::new()?;
        let osrs_client = OSRSClient::new().map_err(DaemonError::OSRSClient)?;
        let consent_client = ConsentClient::new()
            .map_err(|e| DaemonError::OAuthParse(e) )?;
        Ok(Daemon {
            listen_address,
            launcher_client,
            osrs_client,
            consent_client,
            account_session: None,
        })
    }

    pub fn run(&mut self) -> DaemonResult<()> {
        let server_config = tiny_http::ServerConfig {
            addr: self.listen_address.clone(),
            ssl: None,
        };
        // start listening
        let http_server = tiny_http::Server::new(server_config)
            .map_err(|e| DaemonError::HTTPServer(e) )?;
        // runs until server is closed
        http_server.incoming_requests()
            .filter(is_request_local)
            .try_for_each(|r| self.handle_request(r) )?;
        return Err(DaemonError::HTTPServerClosed);
    }

    fn handle_request(&mut self, mut request: Request) -> Result<(), DaemonRequestError> {
        let daemon_request = match DaemonRequestType::from_tiny_http_request(&mut request) {
            Ok(req) => req,
            Err(e) => {
                eprintln!("Error reading request: {}", e);
                return Ok(request.respond(display_error_response(e))?)
            }
        };
        let daemon_response = daemon_request.run(self)
            .unwrap_or_else(|e| DaemonResponse::ErrorStr(e.to_string()) );
        let response: ResponseBox = daemon_response.try_into()
            .map_err(|e| DaemonRequestError::SerializeResponse(e) )?;
        request.respond(response).map_err(|e| DaemonRequestError::IO(e) )
    }
}

#[derive(Debug)]
pub enum LauncherClientError {
    NotInitialized,
    UnknownState,
    RequestToken(RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, StandardErrorResponse<BasicErrorResponseType>>),
    TokenResponseMissingIDToken,
    TokenResponseMissingRefreshToken,
    AccessTokenNotInitialized, RefreshTokenNotInitialized, IDTokenNotInitialized,
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
            LauncherClientError::AccessTokenNotInitialized => write!(f, "Access token not initialized"),
            LauncherClientError::RefreshTokenNotInitialized => write!(f, "Refresh token not initialized"),
            LauncherClientError::IDTokenNotInitialized => write!(f, "ID token not initialized"),
        }
    }
}

trans_tuple_struct!(pub LauncherAuthorizationCode(AuthorizationCode), derive(Clone));
trans_tuple_struct!(pub LauncherClientState(CsrfToken), derive(Clone));
trans_tuple_struct!(LauncherAccessToken(AccessToken), derive(Clone));
trans_tuple_struct!(pub LauncherIDToken(IDToken), derive(Clone, Debug, Serialize, Deserialize));
trans_tuple_struct!(LauncherRefreshToken(RefreshToken));
pub struct LauncherClient {
    oauth: JagexClient,
    state: Option<LauncherClientState>,
    access_token: Option<LauncherAccessToken>,
    id_token: Option<LauncherIDToken>,
    refresh_token: Option<LauncherRefreshToken>,
    login_provider: Option<OSRSLoginProvider>
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

impl LauncherClient {
    fn new() -> DaemonResult<Self> {
        let oauth = load_oauth_client(LAUNCHER_CLIENT_ID, None, LAUNCHER_AUTH_URL, Some(LAUNCHER_TOKEN_URL))
            .map_err(|e| DaemonError::OAuthParse(e))?;
        Ok(LauncherClient {
            oauth,
            state: None,
            access_token: None, id_token: None, refresh_token: None,
            login_provider: None,
        })
    }

    fn tokens<'a>(&'a self) -> LauncherClientResult<(&'a LauncherAccessToken, &'a LauncherRefreshToken, &'a LauncherIDToken)> {
        let at = self.access_token.as_ref().ok_or(LauncherClientError::AccessTokenNotInitialized)?;
        let rt = self.refresh_token.as_ref().ok_or(LauncherClientError::RefreshTokenNotInitialized)?;
        let it = self.id_token.as_ref().ok_or(LauncherClientError::IDTokenNotInitialized)?;
        Ok((at, rt, it))
    }

    fn authorize<'a>(&'a mut self, code: LauncherAuthorizationCode, state: LauncherClientState, _intent: String) -> LauncherClientResult<(&'a LauncherAccessToken, &'a LauncherIDToken, &'a LauncherRefreshToken)> {
        let stored_state = self.state.as_ref().ok_or(LauncherClientError::NotInitialized)?;
        if stored_state.secret() != state.secret() {
            return Err(LauncherClientError::UnknownState);
        }

        let request = self.oauth.exchange_code(code.0);
        let response = request.request(http_client)
            .map_err(|e| LauncherClientError::RequestToken(e) )?;

        let access_token = response.access_token();
        let id_token = response.id_token()
            .ok_or(LauncherClientError::TokenResponseMissingIDToken)?.clone();
        let refresh_token = response.refresh_token()
            .ok_or(LauncherClientError::TokenResponseMissingRefreshToken)?.clone();

        self.login_provider = Some(OSRSLoginProvider::Jagex);
        if let Some(serde_json::Value::String(s)) = id_token.claims.extra.get("login_provider") {
            if s == "runescape" {
                self.login_provider = Some(OSRSLoginProvider::Runescape);
            }
        }

        self.access_token = Some(access_token.clone().into());
        self.id_token = Some(id_token.into());
        self.refresh_token = Some(refresh_token.into());
        Ok((self.access_token.as_ref().unwrap(), self.id_token.as_ref().unwrap(), self.refresh_token.as_ref().unwrap()))
    }

    fn register_auth_url(&mut self) -> String {
        let auth_request = self.oauth.authorize_url(|| CsrfToken::new_random_len(12))
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("offline".to_string()))
            .add_scope(Scope::new("gamesso.token.create".to_string()))
            .add_scope(Scope::new("user.profile.read".to_string()));
        let (url, csrf_token) = auth_request.url();
        self.state = Some(csrf_token.into());
        return url.to_string();
    }
}

#[derive(Debug)]
pub enum OSRSClientError {
    RequestToken(RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, StandardErrorResponse<BasicErrorResponseType>>),
    OAuthURL(url::ParseError),
    TokenResponseMissingRefreshToken,

}
type OSRSClientResult<T> = Result<T, OSRSClientError>;

impl Display for OSRSClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OSRSClientError::RequestToken(e) => write!(f, "Error requesting OSRS access token: {}", match e {
                RequestTokenError::ServerResponse(e) => format!("Server responded with error: {}", e),
                RequestTokenError::Request(e) => format!("Couldn't send request: {}", e),
                RequestTokenError::Parse(e, bytes) => format!("Couldn't parse server response: {}\n{}", e, String::from_utf8_lossy(bytes)),
                RequestTokenError::Other(e) => e.to_string(),
            }),
            OSRSClientError::OAuthURL(e) => write!(f, "Couldn't parse oauth URL: {}", e),
            OSRSClientError::TokenResponseMissingRefreshToken => write!(f, "Token exchange response was missing refresh token"),
        }
    }
}

trans_tuple_struct!(OSRSAccessToken(AccessToken));
trans_tuple_struct!(OSRSRefreshToken(RefreshToken));
pub struct OSRSClient {
    oauth: JagexClient,
    access_token: Option<OSRSAccessToken>,
    refresh_token: Option<OSRSRefreshToken>,
}

impl OSRSClient {
    fn new() -> OSRSClientResult<Self> {
        let oauth = load_oauth_client(OSRS_CLIENT_ID, Some(OSRS_CLIENT_SECRET), OSRS_AUTH_URL, Some(OSRS_TOKEN_URL))
            .map_err(|e| OSRSClientError::OAuthURL(e))?;
        Ok(OSRSClient {
            oauth,
            access_token: None, refresh_token: None,
        })
    }

    fn exchange_jagex_client_access_token<'a>(&'a mut self, access_token: &LauncherAccessToken) -> OSRSClientResult<(&'a OSRSAccessToken, &'a OSRSRefreshToken)> {
        let response = self.oauth.exchange_token(access_token.0.clone()).request(http_client)
            .map_err(OSRSClientError::RequestToken)?;
        let osrs_access_token = response.access_token().clone();
        let osrs_refresh_token = response.refresh_token()
            .ok_or(OSRSClientError::TokenResponseMissingRefreshToken)?.clone();

        self.access_token = Some(osrs_access_token.into());
        self.refresh_token = Some(osrs_refresh_token.into());
        Ok((self.access_token.as_ref().unwrap(), self.refresh_token.as_ref().unwrap()))
    }
}

trans_tuple_struct!(ConsentState(CsrfToken));
pub struct ConsentClient {
    oauth: JagexClient,
    state: Option<ConsentState>,
}

impl ConsentClient {
    fn new() -> Result<ConsentClient, ParseError> {
        let oauth = load_oauth_client(CONSENT_CLIENT_ID, None, LAUNCHER_AUTH_URL, Some(LAUNCHER_TOKEN_URL))?;
        Ok(ConsentClient { oauth, state: None })
    }

    fn register_auth_url(&mut self) -> String {
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
        self.state = Some(token.into());
        return url.to_string();
    }

    fn valid_state(&self, s: &str) -> bool {
        self.state.as_ref().is_some_and(|cs| cs.secret() == s )
    }
}