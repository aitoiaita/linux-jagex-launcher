use std::{time::SystemTime, fmt::Display};

use oauth2::{basic::{BasicErrorResponseType, BasicTokenType}, reqwest::http_client, AccessToken, AuthorizationCode, CsrfToken, EmptyExtraTokenFields, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, RequestTokenError, Scope, StandardErrorResponse, TokenResponse};
use serde::{Serialize, Deserialize};
use url::Url;

use crate::{trans_tuple_struct, xdg::{XDGCredsState, XDGCredsStateResult, XDGCredsStateError}};

use super::{jagex_oauth::{IDToken, JagexClient, TokenResponseWithJWT}, OSRSLoginProvider, load_oauth_client};

const LAUNCHER_CLIENT_ID: &str = "com_jagex_auth_desktop_launcher";
pub const LAUNCHER_AUTH_URL: &str = "https://account.jagex.com/oauth2/auth";
pub const LAUNCHER_TOKEN_URL: &str = "https://account.jagex.com/oauth2/token";
const LAUNCHER_REDIRECT_URI: &str = "https://secure.runescape.com/m=weblogin/launcher-redirect";

#[derive(Debug)]
pub enum LauncherClientError {
    OAuthURL(url::ParseError),
    NotInitialized,
    PKCEVerifierMissing,
    UnknownState,
    RequestToken(RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, StandardErrorResponse<BasicErrorResponseType>>),
    TokenResponseMissingIDToken,
    TokenResponseMissingRefreshToken,
    TokenResponseMissingExpiration,
    CredsState(XDGCredsStateError),
}
type LauncherClientResult<T> = Result<T, LauncherClientError>;

impl Display for LauncherClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LauncherClientError::OAuthURL(e) => write!(f, "Couldn't parse OAuth2 url: {}", e),
            LauncherClientError::NotInitialized => write!(f, "Launcher hasn't been initialized"),
            LauncherClientError::PKCEVerifierMissing => write!(f, "The PKCE verifier is missing"),
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
            LauncherClientError::CredsState(e) => write!(f, "Saved credential error: {}", e),
        }
    }
}

impl From<XDGCredsStateError> for LauncherClientError {
    fn from(e: XDGCredsStateError) -> Self {
        LauncherClientError::CredsState(e)
    }
}

#[derive(Serialize, Deserialize)]
pub struct LauncherClientSession {
    tokens: Option<LauncherTokens>,
    state: Option<LauncherClientState>,
    auth_url: Option<Url>,
}

impl XDGCredsState for LauncherClientSession {
    const CREDS_FILENAME: &'static str = "launcher_session.json";
}

impl LauncherClientSession {
    pub fn new() -> Self {
        LauncherClientSession { tokens: None, state: None, auth_url: None }
    }

    pub fn set_saved_tokens<'a>(&'a mut self, tokens: LauncherTokens) -> XDGCredsStateResult<&'a LauncherTokens> {
        self.tokens = Some(tokens);
        self.write_state_file()?;
        Ok(self.tokens.as_ref().unwrap())
    }

    pub fn set_saved_state<'a>(&'a mut self, state: LauncherClientState) -> XDGCredsStateResult<&'a LauncherClientState> {
        self.state = Some(state);
        self.write_state_file()?;
        Ok(self.state.as_ref().unwrap())
    }

    pub fn set_saved_auth_url<'a>(&'a mut self, auth_url: Url) -> XDGCredsStateResult<&'a Url> {
        self.auth_url = Some(auth_url);
        self.write_state_file()?;
        Ok(self.auth_url.as_ref().unwrap())
    }

    pub fn get_auth_url<'a>(&'a self) -> &'a Option<Url> {
        &self.auth_url
    }

    pub fn get_tokens<'a>(&'a self) -> &'a Option<LauncherTokens> {
        &self.tokens
    }
}

trans_tuple_struct!(pub LauncherAuthorizationCode(AuthorizationCode), derive(Clone, Debug));
trans_tuple_struct!(pub LauncherClientState(CsrfToken), derive(Clone, Debug, Serialize, Deserialize));
trans_tuple_struct!(pub LauncherAccessToken(AccessToken), derive(Clone, Serialize, Deserialize));
trans_tuple_struct!(pub LauncherIDToken(IDToken), derive(Clone, Debug, Serialize, Deserialize));
trans_tuple_struct!(pub LauncherRefreshToken(RefreshToken), derive(Clone, Serialize, Deserialize));
pub struct LauncherClient {
    oauth: JagexClient,
    session: LauncherClientSession,
    pkce_verifier: Option<PkceCodeVerifier>,
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

    pub fn get_login_provider<'a>(&'a self) -> &'a OSRSLoginProvider {
        &self.login_provider
    }

    pub fn get_id_token<'a>(&'a self) -> &'a LauncherIDToken {
        &self.id_token
    }

    pub fn get_access_token<'a>(&'a self) -> &'a LauncherAccessToken {
        &self.access_token
    }

    pub fn get_refresh_token<'a>(&'a self) -> &'a LauncherRefreshToken {
        &self.refresh_token
    }
}

impl LauncherClient {
    pub fn new() -> LauncherClientResult<Self> {
        let oauth = load_oauth_client(LAUNCHER_CLIENT_ID, None, LAUNCHER_AUTH_URL, Some(LAUNCHER_TOKEN_URL))
            .map_err(|e| LauncherClientError::OAuthURL(e))?;
        let session = LauncherClientSession::from_state_file()
            .map_err(LauncherClientError::CredsState)?
            .unwrap_or(LauncherClientSession::new());
        Ok(LauncherClient { oauth, session, pkce_verifier: None })
    }

    pub fn refreshed_tokens<'a>(&'a mut self) -> LauncherClientResult<&'a LauncherTokens> {
        let tokens = match self.session.tokens.as_ref() {
            Some(t) => t,
            None => return Err(LauncherClientError::NotInitialized)
        };
        let tokens = tokens.clone();
        if tokens.expired() {
            tracing::info!("refreshed expired tokens");
            Ok(self.session.set_saved_tokens(tokens.refreshed(&self.oauth)?)?)
        } else {
            Ok(self.session.tokens.as_ref().unwrap())
        }
    }

    fn handle_token_response<'a>(&'a mut self, response: TokenResponseWithJWT<EmptyExtraTokenFields, BasicTokenType>) -> LauncherClientResult<&'a LauncherTokens> {
        Ok(self.session.set_saved_tokens(LauncherTokens::from_token_response(response)?)?)
    }

    pub fn authorize<'a>(&'a mut self, code: LauncherAuthorizationCode, state: LauncherClientState, _intent: String) -> LauncherClientResult<&'a LauncherTokens> {
        // return error not initialized if state hasn't been set. also return error if unexpected state.
        let stored_state = self.session.state.as_ref().ok_or(LauncherClientError::NotInitialized)?;
        if stored_state.secret() != state.secret() {
            return Err(LauncherClientError::UnknownState);
        }


        let pkce_verifier = self.pkce_verifier
            .take()
            .ok_or(LauncherClientError::PKCEVerifierMissing)?;

        let request = self.oauth
            .exchange_code(code.0)
            .set_redirect_uri(std::borrow::Cow::Owned(RedirectUrl::new(LAUNCHER_REDIRECT_URI.to_string()).unwrap()))
            .set_pkce_verifier(pkce_verifier);

            let response = request.request(http_client).map_err(|e| LauncherClientError::RequestToken(e) )?;

        self.handle_token_response(response)
    }

    pub fn register_auth_url(&mut self) -> LauncherClientResult<String> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256_len(64);

        self.pkce_verifier = Some(pkce_verifier);

        let auth_request = self.oauth
            .authorize_url(|| CsrfToken::new_random_len(12))
            .set_pkce_challenge(pkce_challenge)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("offline".to_string()))
            .add_scope(Scope::new("gamesso.token.create".to_string()))
            .add_scope(Scope::new("user.profile.read".to_string()))
            .set_redirect_uri(std::borrow::Cow::Owned(RedirectUrl::new(LAUNCHER_REDIRECT_URI.to_string()).unwrap()));
        let (url, csrf_token) = auth_request.url();
        let url_str = url.to_string();
        self.session.set_saved_auth_url(url)?;
        self.session.set_saved_state(csrf_token.into())?;
        return Ok(url_str);
    }

    pub fn get_session<'a>(&'a self) -> &'a LauncherClientSession {
        &self.session
    }
}
