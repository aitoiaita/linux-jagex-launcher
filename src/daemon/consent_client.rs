use std::fmt::Display;

use oauth2::{CsrfToken, RedirectUrl, ResponseType, Scope};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    trans_tuple_struct,
    xdg::{XDGCredsState, XDGCredsStateError},
};

use super::{
    jagex_oauth::JagexClient,
    launcher_client::{LAUNCHER_AUTH_URL, LAUNCHER_TOKEN_URL},
    load_oauth_client,
};

const CONSENT_CLIENT_ID: &str = "1fddee4e-b100-4f4e-b2b0-097f9088f9d2";

#[derive(Debug)]
pub enum ConsentClientError {
    CredsState(XDGCredsStateError),
    OAuthURL(url::ParseError),
}
type ConsentClientResult<T> = Result<T, ConsentClientError>;

impl Display for ConsentClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsentClientError::CredsState(e) => write!(f, "Saved credential error: {}", e),
            ConsentClientError::OAuthURL(e) => write!(f, "Couldn't parse OAuth2 url: {}", e),
        }
    }
}

impl From<XDGCredsStateError> for ConsentClientError {
    fn from(e: XDGCredsStateError) -> Self {
        ConsentClientError::CredsState(e)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ConsentClientSession {
    state: Option<ConsentState>,
    auth_url: Option<Url>,
}

impl XDGCredsState for ConsentClientSession {
    const CREDS_FILENAME: &'static str = "consent_session.json";
}

impl ConsentClientSession {
    fn new() -> Self {
        ConsentClientSession {
            state: None,
            auth_url: None,
        }
    }

    pub fn set_saved_state<'a>(
        &'a mut self,
        state: ConsentState,
    ) -> ConsentClientResult<&'a ConsentState> {
        self.state = Some(state);
        self.write_state_file()?;
        Ok(self.state.as_ref().unwrap())
    }

    pub fn set_saved_auth_url<'a>(&'a mut self, auth_url: Url) -> ConsentClientResult<&'a Url> {
        self.auth_url = Some(auth_url);
        self.write_state_file()?;
        Ok(self.auth_url.as_ref().unwrap())
    }

    pub fn get_auth_url<'a>(&'a self) -> &'a Option<Url> {
        &self.auth_url
    }
}

trans_tuple_struct!(pub ConsentState(CsrfToken), derive(Serialize, Deserialize));
pub struct ConsentClient {
    oauth: JagexClient,
    session: ConsentClientSession,
}

impl ConsentClient {
    pub fn new() -> ConsentClientResult<ConsentClient> {
        let oauth = load_oauth_client(
            CONSENT_CLIENT_ID,
            None,
            LAUNCHER_AUTH_URL,
            Some(LAUNCHER_TOKEN_URL),
        )
        .map_err(ConsentClientError::OAuthURL)?;
        let session =
            ConsentClientSession::from_state_file()?.unwrap_or(ConsentClientSession::new());
        Ok(ConsentClient { oauth, session })
    }

    pub fn register_auth_url(&mut self) -> ConsentClientResult<String> {
        let nonce: String = thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        let (url, token) = self
            .oauth
            .authorize_url(CsrfToken::new_random)
            .use_implicit_flow()
            .set_response_type(&ResponseType::new("id_token code".to_string()))
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("offline".to_string()))
            .add_extra_param("nonce", nonce)
            .set_redirect_uri(std::borrow::Cow::Owned(
                RedirectUrl::new("http://localhost".to_string()).unwrap(),
            ))
            .url();
        let url_str = self.session.set_saved_auth_url(url)?.clone().into();
        self.session.set_saved_state(token.into())?;
        return Ok(url_str);
    }

    pub fn valid_state(&self, s: &str) -> bool {
        self.session
            .state
            .as_ref()
            .is_some_and(|cs| cs.secret() == s)
    }

    pub fn get_session<'a>(&'a self) -> &'a ConsentClientSession {
        &self.session
    }
}
