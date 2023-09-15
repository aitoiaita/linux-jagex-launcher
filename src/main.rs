use oauth2::url::ParseError;
use oauth2::{
    AuthorizationCode,
    AuthUrl,
    ClientId,
    ClientSecret,
    CsrfToken,
    Scope,
    TokenResponse,
    TokenUrl
};
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;

use std::borrow::Cow;
use std::io::Write;

const LAUNCHER_CLIENT_ID: &str = "com_jagex_auth_desktop_launcher";
const LAUNCHER_AUTH_URL: &str = "https://account.jagex.com/oauth2/auth";
const LAUNCHER_TOKEN_URL: &str = "https://account.jagex.com/oauth2/token";

const OSRS_CLIENT_ID: &str = "com_jagex_auth_desktop_osrs";
const OSRS_CLIENT_SECRET: &str = "public";
const OSRS_AUTH_URL: &str = "https://auth.jagex.com/shield/oauth/auth";
const OSRS_TOKEN_URL: &str = "https://auth.jagex.com/shield/oauth/token";

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

fn read_auth_code() -> std::io::Result<AuthorizationCode> {
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer)?;
    while let Some(byte) = buffer.as_bytes().last() {
        if *byte != b'\r' && *byte != b'\n' {
            break;
        }
        buffer.pop();
    }
    return Ok(AuthorizationCode::new(buffer)); 
}

fn main() -> std::io::Result<()> {
    let launcher_client = load_oauth_client(LAUNCHER_CLIENT_ID, None, LAUNCHER_AUTH_URL, Some(LAUNCHER_TOKEN_URL))
        .unwrap_or_else(|e| panic!("Error parsing launcher oauth client URL: {}", e) );

    let osrs_client = load_oauth_client(OSRS_CLIENT_ID, Some(OSRS_CLIENT_SECRET), OSRS_AUTH_URL, Some(OSRS_TOKEN_URL))
        .unwrap_or_else(|e| panic!("Error parsing OSRS oauth client URL: {}", e) );

    let auth_request = launcher_client.authorize_url(|| CsrfToken::new_random_len(12))
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("offline".to_string()))
        .add_scope(Scope::new("gamesso.token.create".to_string()))
        .add_scope(Scope::new("user.profile.read".to_string()));

    let (url, csrf_token) = auth_request.url();
    println!("Please follow the link and paste your code\n{} ", url.as_str());

    let auth_code = read_auth_code()
        .unwrap_or_else(|error| panic!("Couldn't read authorization code: {}", error));

    let launcher_token_request = launcher_client.exchange_code(auth_code);
    let launcher_token = launcher_token_request.request(http_client)
        .unwrap_or_else(|e| panic!("Couldn't request launcher code exchange: {}", e));

    println!("Got launcher access token: {}", launcher_token.access_token().secret());
    let osrs_token_request = osrs_client.exchange_token(launcher_token.access_token().clone());
    let osrs_token_response = osrs_token_request.request(http_client)
        .unwrap_or_else(|e| panic!("Couldn't exchange launcher token for OSRS token: {}", e) );

    println!("JX_ACCESS_TOKEN={}", osrs_token_response.access_token().secret());
    if let Some(refresh_token) = osrs_token_response.refresh_token() {
        println!("JX_REFRESH_TOKEN={}", refresh_token.secret());
    }

    Ok(())
}
