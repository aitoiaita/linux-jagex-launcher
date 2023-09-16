use interprocess::os::unix::udsocket::{UdStreamListener, UdStream};
use oauth2::{
    AccessToken,
    AuthorizationCode,
    AuthUrl,
    ClientId,
    ClientSecret,
    CsrfToken,
    RefreshToken,
    RequestTokenError,
    Scope,
    TokenResponse,
    TokenUrl,
    basic::{BasicClient, BasicErrorResponse, BasicRequestTokenError, BasicTokenResponse},
    reqwest::http_client,
    url::ParseError,
};
use serde::{Deserialize, Serialize};

use std::{collections::{
    HashMap, hash_map::RandomState
}, str::FromStr, process::{Command, Child}, time::{SystemTime, Duration}};
use std::fmt::Display;
use std::io::{Write, BufReader, BufRead, BufWriter};

const LAUNCHER_CLIENT_ID: &str = "com_jagex_auth_desktop_launcher";
const LAUNCHER_AUTH_URL: &str = "https://account.jagex.com/oauth2/auth";
const LAUNCHER_TOKEN_URL: &str = "https://account.jagex.com/oauth2/token";

const OSRS_CLIENT_ID: &str = "com_jagex_auth_desktop_osrs";
const OSRS_CLIENT_SECRET: &str = "public";
const OSRS_AUTH_URL: &str = "https://auth.jagex.com/shield/oauth/auth";
const OSRS_TOKEN_URL: &str = "https://auth.jagex.com/shield/oauth/token";

const UNIX_SOCKET_PATH: &str = "/tmp/tutisland";

enum LauncherError {
    ParseURI(ParseJagexLauncherURIError),
    ParseCommand(ParseCommandError),
    IO(std::io::Error),
    OAuth2(OAuth2Error)
}
type LauncherResult<T> = Result<T, LauncherError>;

impl From<ParseJagexLauncherURIError> for LauncherError {
    fn from(e: ParseJagexLauncherURIError) -> Self {
        LauncherError::ParseURI(e)
    }
}

impl From<std::io::Error> for LauncherError {
    fn from(e: std::io::Error) -> Self {
        LauncherError::IO(e)
    }
}

impl From<serde_json::Error> for LauncherError {
    fn from(e: serde_json::Error) -> Self {
        LauncherError::ParseCommand(ParseCommandError::JSON(e))
    }
}

impl From<BasicRequestTokenError<oauth2::reqwest::Error<reqwest::Error>>> for LauncherError {
    fn from(e: BasicRequestTokenError<oauth2::reqwest::Error<reqwest::Error>>) -> Self {
        LauncherError::OAuth2(OAuth2Error::RequestToken(oauth2::RequestTokenError::Request(e)))
    }
}

impl Display for LauncherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LauncherError::ParseURI(e) => write!(f, "Failed to parse URI - {}", e),
            LauncherError::IO(e) => write!(f, "IO error - {}", e),
            LauncherError::ParseCommand(e) => write!(f, "Failed to parse IPC command - {}", e),
            LauncherError::OAuth2(e) => write!(f, "OAuth2 flow error - {}", e)
        }
    }
}

enum OAuth2Error {
    RequestToken(BasicRequestTokenError<RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, BasicErrorResponse>>),
    MissingRefreshToken
}

impl Display for OAuth2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OAuth2Error::RequestToken(e) => write!(f, "Couldn't request token exchange: {}", e),
            OAuth2Error::MissingRefreshToken => write!(f, "Missing refresh_token in auth response")
        }
    }
}

enum ParseCommandError {
    JSON(serde_json::Error)
}

impl Display for ParseCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParseCommandError::JSON(e) => write!(f, "JSON parse error: {}", e)
        }
    }
}

enum ParseJagexLauncherURIError {
    Protocol,
    Component(String),
    MissingCode,
    MissingState,
    MissingIntent,
    Other(ParseError)
}

impl Display for ParseJagexLauncherURIError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseJagexLauncherURIError::Protocol => write!(f, "Missing or incorrect protocol"),
            ParseJagexLauncherURIError::Component(s) => write!(f, "Malformed component: '{}'", s),
            ParseJagexLauncherURIError::MissingCode => write!(f, "Missing 'code' component"),
            ParseJagexLauncherURIError::MissingState => write!(f, "Missing 'state' component"),
            ParseJagexLauncherURIError::MissingIntent => write!(f, "Missing 'intent' component"),
            ParseJagexLauncherURIError::Other(e) => write!(f, "{}", e)
        }
    }
}

struct JagexLauncherURI {
    code: AuthorizationCode,
    state: String,
    _intent: String
}

impl<'a> std::str::FromStr for JagexLauncherURI {
    type Err = ParseJagexLauncherURIError;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let uri_body = str.strip_prefix("jagex:")
            .ok_or(ParseJagexLauncherURIError::Protocol)?;

        let uri_component_list: Vec<(&str, &str)> = uri_body
            .split(",")
            .map(|c| c.split_once("=").ok_or_else(|| ParseJagexLauncherURIError::Component(c.to_string())) )
            .collect::<Result<Vec<(&str, &str)>, ParseJagexLauncherURIError>>()?;
        let uri_components: HashMap<&str, &str, RandomState> = HashMap::from_iter(uri_component_list);

        let uri_code = uri_components.get("code")
            .ok_or(ParseJagexLauncherURIError::MissingCode)
            .map(|code| AuthorizationCode::new(code.to_string()) )?;
        let uri_state = uri_components.get("state")
            .ok_or(ParseJagexLauncherURIError::MissingState)?;
        let uri_intent = uri_components.get("intent")
            .ok_or(ParseJagexLauncherURIError::MissingIntent)?;

        return Ok(JagexLauncherURI { 
            code: uri_code,
            state: uri_state.to_string(),
            _intent: uri_intent.to_string()
        });
    }
}

fn handle_ipc_error(res: std::io::Result<UdStream>) -> Option<UdStream> {
    match res {
        Ok(val) => Some(val),
        Err(err) => {
            eprintln!("IPC error: {}", err);
            None
        }
    }
}

struct LauncherResource {
    access_token: Option<AccessToken>,
    refresh_token: Option<RefreshToken>,
    expiration: Option<SystemTime>
}

impl LauncherResource {
    fn empty() -> Self {
        LauncherResource { access_token: None, refresh_token: None, expiration: None }
    }

    fn update_tokens(&mut self, response: BasicTokenResponse) -> LauncherResult<()> {
        self.access_token = Some(response.access_token().clone());
        self.refresh_token = Some(response.refresh_token().ok_or(LauncherError::OAuth2(OAuth2Error::MissingRefreshToken))?.clone());
        let expires_in = response.expires_in().unwrap_or(Duration::new(60 * 30, 0)); // assume 30 minute default expiration
        self.expiration = Some(SystemTime::now() + expires_in);
        Ok(())
    }

    fn tokens<'a>(&'a self) -> Option<(&'a AccessToken, &'a RefreshToken)> {
        if let Some(access_token) = &self.access_token {
            if let Some(refresh_token) = &self.refresh_token {
                return Some((access_token, refresh_token));
            }
        }
        None
    }
}

struct Launcher {
    osrs_client: BasicClient,
    osrs_resource: LauncherResource,
    jagex_client: BasicClient,
    jagex_resource: LauncherResource
}

fn load_oauth_client(client_id: &str, client_secret: Option<&str>, auth_url: &str, token_url: Option<&str>) -> Result<BasicClient, ParseError> {
    let client_id = ClientId::new(client_id.to_string());
    let client_secret = match client_secret {
        Some(url) => Some(ClientSecret::new(url.to_string())),
        None => None
    };
    let auth_url = AuthUrl::new(auth_url.to_string())?;
    let token_url = match token_url {
        Some(url) => Some(TokenUrl::new(url.to_string())?),
        None => None
    };
    let client = BasicClient::new(client_id, client_secret, auth_url, token_url);
    Ok(client)
}

fn run_runelite(access_token: &AccessToken, refresh_token: &RefreshToken) -> LauncherResult<Child> {
    return Ok(Command::new("runelite")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env("JX_ACCESS_TOKEN", access_token.secret())
        .env("JX_REFRESH_TOKEN", refresh_token.secret())
        .spawn()?);
}

impl Launcher {
    fn exchange_auth_code(&mut self, code: &AuthorizationCode) -> LauncherResult<()> {
        let token_response = self.jagex_client.exchange_code(code.clone()).request(http_client)?;
        self.jagex_resource.update_tokens(token_response)?;
        Ok(())
    }

    fn launch(&mut self) -> LauncherResult<LauncherCommandResponse> {
        if let Some((access_token, refresh_token)) = self.jagex_resource.tokens()  {
            let osrs_token_request = self.osrs_client.exchange_token(access_token.clone());
            let osrs_token_response = osrs_token_request.request(http_client)
                .unwrap_or_else(|e| panic!("Couldn't exchange launcher token for OSRS token: {}", e) );
        
            self.osrs_resource.update_tokens(osrs_token_response)?;

            if let Some((access_token, refresh_token)) = self.osrs_resource.tokens() {
                println!("JX_ACCESS_TOKEN={}", access_token.secret());
                println!("JX_REFRESH_TOKEN={}", refresh_token.secret());
                run_runelite(access_token, refresh_token)?;
                Ok(LauncherCommandResponse::Ok)
            } else {
                Ok(LauncherCommandResponse::Error("Couldn't fetch OSRS access_token and refresh_token".to_string()))
            }
        } else {
            let auth_request = self.jagex_client.authorize_url(|| CsrfToken::new_random_len(12))
                .add_scope(Scope::new("openid".to_string()))
                .add_scope(Scope::new("offline".to_string()))
                .add_scope(Scope::new("gamesso.token.create".to_string()))
                .add_scope(Scope::new("user.profile.read".to_string()));
            // TODO validate csrf token
            let (url, _csrf_token) = auth_request.url();
            Ok(LauncherCommandResponse::Authenticate { url: url.to_string() })
        }
    }

    fn new() -> LauncherResult<Self> {
        let jagex_client = load_oauth_client(LAUNCHER_CLIENT_ID, None, LAUNCHER_AUTH_URL, Some(LAUNCHER_TOKEN_URL))
            .map_err(|e| LauncherError::ParseURI(ParseJagexLauncherURIError::Other(e)) )?;
        let osrs_client = load_oauth_client(OSRS_CLIENT_ID, Some(OSRS_CLIENT_SECRET), OSRS_AUTH_URL, Some(OSRS_TOKEN_URL))
            .map_err(|e| LauncherError::ParseURI(ParseJagexLauncherURIError::Other(e)) )?;
        Ok(Launcher {
            jagex_client,
            jagex_resource: LauncherResource::empty(),
            osrs_client,
            osrs_resource: LauncherResource::empty()
        })
    }

    fn run_loop(&mut self) -> LauncherResult<()> {
        let listener = UdStreamListener::bind_with_drop_guard(UNIX_SOCKET_PATH)?;
        for client in listener.incoming().filter_map(handle_ipc_error) {
            // Read and parse a command
            let mut reader = BufReader::new(client);
            let mut command_buffer = String::new();
            reader.read_line(&mut command_buffer)?;
            let command: LauncherCommand = serde_json::from_str(&command_buffer)?;

            // Run the command and generate a response
            let mut response_buffer = serde_json::to_string(&command.run(self))?;
            response_buffer.push('\n');

            // Write the response and clean up
            let mut client = reader.into_inner();
            client.write_all(response_buffer.as_bytes())?;
            client.shutdown(std::net::Shutdown::Both)?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
enum LauncherCommand {
    Launch,
    AuthCode { auth_code: AuthorizationCode }
}

impl LauncherCommand {
    fn run(&self, launcher: &mut Launcher) -> LauncherCommandResponse {
        match self {
            LauncherCommand::AuthCode { auth_code } => {
                let token_req = launcher.exchange_auth_code(auth_code);
                match token_req {
                    Ok(_) => LauncherCommandResponse::Ok,
                    Err(e) => LauncherCommandResponse::Error(e.to_string())
                }
            },
            LauncherCommand::Launch => {
                match launcher.launch() {
                    Ok(r) => r,
                    Err(e) => LauncherCommandResponse::Error(e.to_string())
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
enum LauncherCommandResponse {
    Ok,
    Authenticate { url: String },
    Error(String)
}

impl LauncherCommandResponse {
    fn error<'a>(&'a self) -> Option<&'a str> {
        if let LauncherCommandResponse::Error(error_string) = self {
            Some(&error_string)
        } else {
            None
        }
    }
}

impl LauncherCommandResponse {
    fn summary(&self) -> String {
        match self {
            LauncherCommandResponse::Ok => "Ok".to_string(),
            LauncherCommandResponse::Authenticate { url } => format!("Please visit the following URL: {}", url).to_string(),
            LauncherCommandResponse::Error(estr) => estr.to_string()
        }
    }
}

struct Client;

impl Client {
    fn connect_ipc() -> LauncherResult<UdStream> {
        return Ok(UdStream::connect(UNIX_SOCKET_PATH)?);
    }

    fn send_command(command: &LauncherCommand) -> LauncherResult<LauncherCommandResponse> {
        let ipc_socket = Client::connect_ipc()?;
        let mut serialized_command = serde_json::to_string(command)?;
        serialized_command.push('\n');

        let mut writer = BufWriter::new(ipc_socket);
        writer.write_all(serialized_command.as_bytes())?;

        let ipc_socket = writer.into_inner().unwrap();
        let mut reader = BufReader::new(ipc_socket);
        let mut response_buffer = String::new();
        reader.read_line(&mut response_buffer)?;
        Ok(serde_json::from_str(&response_buffer)?)
    }

    fn launch() -> LauncherResult<LauncherCommandResponse> {
        Client::send_command(&LauncherCommand::Launch)
    }

    fn handle_jagex_uri(uri_str: &str) -> LauncherResult<LauncherCommandResponse> {
        let uri = JagexLauncherURI::from_str(uri_str)?;
        Client::send_command(&LauncherCommand::AuthCode { auth_code: uri.code })
    }
}

fn ipc_socket_exists() -> bool {
    match std::fs::metadata(UNIX_SOCKET_PATH) {
        Ok(_) => true,
        Err(_) => false
    }
}

// TODO:
//  > refresh expired tokens automatically
//  > multiple account support
fn main() -> std::io::Result<()> {
    let program_args: Vec<String> = std::env::args().collect();
    if let Some(uri_str) = program_args.get(1) {
        let response = Client::handle_jagex_uri(uri_str)
            .unwrap_or_else(|e| panic!("Error handling URI: {}", e) );
        response.error().map(|e| panic!("Error from server while handling URI: {}", e) );
        let response = Client::launch()
            .unwrap_or_else(|e| panic!("Error sending launch request: {}", e) ) ;
        response.error().map(|e| panic!("Error from server while sending launch request: {}", e) );
        return Ok(());
    } else {
        if ipc_socket_exists() {
            println!("Sending launch request to daemon");
            let response = Client::launch()
                .unwrap_or_else(|e| panic!("Error sending launch request: {}", e) );
            println!("{}", response.summary());
        } else {
            println!("Running daemon");
            let mut launcher = Launcher::new()
                .unwrap_or_else(|e| panic!("Error creating launcher daemon: {}", e) );
            launcher.run_loop()
                .unwrap_or_else(|e| panic!("Error running launcher daemon: {}", e) );
        }
    }

    Ok(())
}
