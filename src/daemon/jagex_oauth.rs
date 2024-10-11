use std::{
    collections::BTreeMap, fmt::Display, str::FromStr, string::FromUtf8Error, time::Duration,
};

use base64::{DecodeError, Engine};
use chrono::{serde::ts_seconds, DateTime, Utc};
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    helpers, AccessToken, Client, EmptyExtraTokenFields, ExtraTokenFields, RefreshToken, Scope,
    StandardRevocableToken, TokenResponse, TokenType,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type JagexClient = Client<
    BasicErrorResponse,
    TokenResponseWithJWT<EmptyExtraTokenFields, BasicTokenType>,
    BasicTokenType,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
>;

#[derive(Debug)]
pub enum JWTPart {
    Header,
    Claims,
    Signature,
}
impl Display for JWTPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JWTPart::Header => write!(f, "header"),
            JWTPart::Claims => write!(f, "claims"),
            JWTPart::Signature => write!(f, "signature"),
        }
    }
}

#[derive(Debug)]
pub enum JWTParseError {
    ExtraSegments(usize),
    Missing(JWTPart),
    Base64Decode(JWTPart, DecodeError),
    Utf8Decode(JWTPart, FromUtf8Error),
    Parse(JWTPart, serde_json::Error),
}

impl Display for JWTParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExtraSegments(n) => write!(f, "{} too many segments", n),
            Self::Missing(part) => write!(f, "Missing {} section", part),
            Self::Base64Decode(part, e) => {
                write!(f, "Couldn't decode base64 encoded {}: {}", part, e)
            }
            Self::Utf8Decode(part, e) => write!(f, "Couldn't decode utf8 encoded {}: {}", part, e),
            Self::Parse(part, e) => write!(f, "Couldn't parse {} json: {}", part, e),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWTHeader {
    pub typ: String,
    #[serde(rename = "alg")]
    pub algorithm: String,
    #[serde(rename = "kid")]
    pub key_id: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWTClaims {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "exp", with = "ts_seconds")]
    pub expiration: DateTime<Utc>,
    #[serde(rename = "aud")]
    pub audience: Vec<String>,
    #[serde(rename = "sub")]
    pub subject: String,
    #[serde(rename = "iat", with = "ts_seconds")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "jti")]
    pub jwt_id: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct IDToken {
    pub original: String,
    pub header: JWTHeader,
    pub claims: JWTClaims,
    pub signature: Vec<u8>,
}

impl Serialize for IDToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.original)
    }
}

impl<'de> Deserialize<'de> for IDToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf = String::deserialize(deserializer)?;
        IDToken::from_str(&buf).map_err(serde::de::Error::custom)
    }
}

impl FromStr for IDToken {
    type Err = JWTParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b64_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut segments = s.split(".");
        let header_segment = segments
            .next()
            .map(|s| b64_engine.decode(s))
            .ok_or(JWTParseError::Missing(JWTPart::Header))?
            .map_err(|e| JWTParseError::Base64Decode(JWTPart::Header, e))?;
        let claims_segment = segments
            .next()
            .map(|s| b64_engine.decode(s))
            .ok_or(JWTParseError::Missing(JWTPart::Claims))?
            .map_err(|e| JWTParseError::Base64Decode(JWTPart::Claims, e))?;
        let signature_segment = segments
            .next()
            .map(|s| b64_engine.decode(s))
            .ok_or(JWTParseError::Missing(JWTPart::Signature))?
            .map_err(|e| JWTParseError::Base64Decode(JWTPart::Signature, e))?;

        let remaining_segments = segments.count();
        if remaining_segments != 0 {
            return Err(JWTParseError::ExtraSegments(remaining_segments));
        }

        let header_str = String::from_utf8(header_segment)
            .map_err(|e| JWTParseError::Utf8Decode(JWTPart::Header, e))?;
        let header: JWTHeader = serde_json::from_str(&header_str)
            .map_err(|e| JWTParseError::Parse(JWTPart::Header, e))?;

        let claims_str = String::from_utf8(claims_segment)
            .map_err(|e| JWTParseError::Utf8Decode(JWTPart::Claims, e))?;
        let claims: JWTClaims = serde_json::from_str(&claims_str)
            .map_err(|e| JWTParseError::Parse(JWTPart::Claims, e))?;

        Ok(IDToken {
            header,
            claims,
            signature: signature_segment,
            original: s.to_string(),
        })
    }
}

///
/// Standard OAuth2 token response.
///
/// This struct includes the fields defined in
/// [Section 5.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.1), as well as
/// extensions defined by the `EF` type parameter.
///
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenResponseWithJWT<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    access_token: AccessToken,
    #[serde(bound = "TT: TokenType")]
    #[serde(deserialize_with = "helpers::deserialize_untagged_enum_case_insensitive")]
    token_type: TT,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<RefreshToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    id_token: Option<IDToken>,
    #[serde(rename = "scope")]
    #[serde(deserialize_with = "helpers::deserialize_space_delimited_vec")]
    #[serde(serialize_with = "helpers::serialize_space_delimited_vec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    scopes: Option<Vec<Scope>>,

    #[serde(bound = "EF: ExtraTokenFields")]
    #[serde(flatten)]
    extra_fields: EF,
}

impl<EF, TT> TokenResponseWithJWT<EF, TT>
where
    EF: ExtraTokenFields,
    TT: TokenType,
{
    ///
    /// OPTIONAL, if the 'openid' scope wasn't requested; otherwise REQUIRED.
    ///
    pub fn id_token(&self) -> Option<&IDToken> {
        self.id_token.as_ref()
    }
}

impl<EF> TokenResponse<BasicTokenType> for TokenResponseWithJWT<EF, BasicTokenType>
where
    EF: ExtraTokenFields,
    BasicTokenType: TokenType,
{
    ///
    /// REQUIRED. The access token issued by the authorization server.
    ///
    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    ///
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    /// But in this particular case as the service is non compliant, it has a default value
    ///
    fn token_type(&self) -> &BasicTokenType {
        &self.token_type
    }
    ///
    /// RECOMMENDED. The lifetime in seconds of the access token. For example, the value 3600
    /// denotes that the access token will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide the expiration time via
    /// other means or document the default value.
    ///
    fn expires_in(&self) -> Option<Duration> {
        self.expires_in.map(Duration::from_secs)
    }
    ///
    /// OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in
    /// [Section 6](https://tools.ietf.org/html/rfc6749#section-6).
    ///
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }
    ///
    /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The
    /// scipe of the access token as described by
    /// [Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3). If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    ///
    fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }
}
