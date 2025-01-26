//! This crate implements middleware to authenticate requests to [axum]. Overall
//! the aim is to provide simple, passwordless authentication for secure network
//! communication. A session key is stored in a cookie and signed with a secret
//! (using crypto implementations in [the `tower-cookies`
//! crate](https://crates.io/crates/tower-cookies)). Due to the signature, the
//! session key cannot be modified. Aside from storing the secret, the system is
//! stateless, requiring no storage on the server.
//!
//! In the normal case, a token is provided out-of-band to the user. For
//! example, the user will start the server from an SSH session and copy the
//! token to their browser. Alternatively, if the connection is defined as
//! trusted (e.g. if it is a loopback connection), authentication occurs without
//! any check.
//!
//! This is useful in cases where a user launches a server process and wants to
//! achieve network-based control of the server without the server exposing this
//! functionality to unauthenticated network connections. In this scenario, if
//! the user provides the correct token in the URL upon initial connection, the
//! server sets a cookie in the user's browser and subsequent requests are
//! automatically validated with no further token in the URL.
//!
//! The user does not need an account, Passkey, OpenID Connect (OIDC), OAuth,
//! OAuth2, FIDO U2F, FIDO2, WebAuthn, SAML, LDAP, Kerberos, RADIUS, or SSO
//! credentials. The developer also does not need to configure these services.
//! Rather, the user uses a URL with the correct token in the query parameters
//! when initially connecting to the server.
//!
//! # Typical flow
//!
//! 1. A user starts or connects to a server and the user is given an initial
//!    authentication token. (For example, the server prints or shows a QR code
//!    containing a URL. The URL includes the token.)
//! 2. The user connects via a browser to the server. In the first HTTP request
//!    from the user, the token is included in the query parameter in the URL.
//! 3. A new [SessionKey] is included as a new cookie in the HTTP response to
//!    the user. The cookie is stored by the user's browser. On the server, the
//!    request is further processed by the next service with session key
//!    information being made available.
//! 4. Subsequent requests from the user browser include the newly set cookie
//!    (and no longer include the token in the URL) and the middleware makes the
//!    session key information available to the next service.
//!
//! # Trusted connection flow
//!
//! In case of a trusted connection, no token is required for initial
//! authentication. The session key is still issued as above.
//!
//! # Cookie expiration
//!
//! The cookies stored on the clients' browser can be persisted (the response
//! sets a cookie with an `Expires` field) or they can be "session cookies". If
//! the `expires` field in [AuthConfig] is set to `None`, a successful auth will
//! set a "session cookie", meaning the cookie does not contain an `Expires` or
//! `Max-age` key. Otherwise, when the `expires` field is set, browsers will
//! store the cookie persistently. (Note that this expiry information cannot be
//! used for security purposes as it is entirely controlled by the clients'
//! browser.)
//!
//! # Session Key expiration
//!
//! The signature on the cookies containing session keys is valid until the
//! persistent secret is changed. (If you need to invalidate keys, switch the
//! persistent secret or use a more full-featured authentication middleware.)
//!
//! # For more extensive needs
//!
//! If this crate does not meet your needs, check
//! [`axum-login`](https://crates.io/crates/axum-login).
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use axum::{
    extract::{FromRequestParts, Request},
    http::{request::Parts, StatusCode},
    response::Response,
    BoxError,
};

use cookie::{
    time::{Duration, OffsetDateTime},
    Key,
};
use futures_util::future::BoxFuture;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

/// One or more validation errors
#[derive(thiserror::Error, Debug)]
#[error("one or more validation errors")]
pub struct ValidationErrors(Vec<String>);

impl ValidationErrors {
    /// Return an iterator over the validation errors that ocurred
    pub fn errors(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

/// Identifier for each session (one per client browser).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SessionKey(pub uuid::Uuid);

impl SessionKey {
    /// Ensures at compile-time that a session key is present.
    ///
    /// A handler which called this method can only be called with a (valid)
    /// session key and thus do not present a security hole. Furthermore, having
    /// such a method call in the handler prevents accidental removal of the
    /// `SessionKey` argument to the handler.
    pub fn is_present(&self) {}
}

impl Default for SessionKey {
    fn default() -> Self {
        SessionKey(uuid::Uuid::new_v4())
    }
}

/// Configuration for URI query parameters to implement token-based
/// authentication.
#[derive(Clone, Debug)]
pub struct TokenConfig {
    /// The key of the token in the URI query parameters.
    pub name: String,
    /// The value of the access-granting token in the URI query parameters.
    ///
    /// This is a secret shared with users (which should therefore be
    /// short-lived).
    pub value: String,
}

impl TokenConfig {
    /// Generate a new token value.
    pub fn new_token(name: &str) -> Self {
        Self {
            name: name.into(),
            value: format!("{}", uuid::Uuid::new_v4()),
        }
    }
    /// Parse token from URL query
    fn parse_token_from_uri_query(&self, req: &Request) -> bool {
        use std::borrow::Cow;

        let query = req.uri().query();
        let query_pairs = url::form_urlencoded::parse(query.unwrap_or("").as_bytes());
        for (key, value) in query_pairs {
            if key == Cow::Borrowed(&self.name) && self.value.as_str() == value {
                return true;
            }
        }
        false
    }
}

/// Configuration for [AuthLayer] and [AuthMiddleware].
#[derive(Clone, Debug)]
pub struct AuthConfig<'a> {
    /// The cookie name
    ///
    /// This is the name of the cookie stored in the clients' browsers.
    pub cookie_name: &'a str,
    /// A long lived secret used to sign cookies set to the users.
    ///
    /// The secret is not shared with users.
    ///
    /// All issued session keys are valid as long as the persistent secret is
    /// unchanged. There is no mechanism to invalidate individual sessions.
    pub persistent_secret: Key,
    /// The authentication token value and its configuration.
    ///
    /// Set to `None` if the entire connection is trusted (e.g. it is on a
    /// loopback interface). In this case, token checking is disabled but still
    /// [SessionKey] is still provided by [AuthMiddleware].
    pub token_config: Option<TokenConfig>,
    /// If set, the newly set cookie has an Expires field which corresponds the
    /// value set in `expires`. If not set, the cookie does not have an
    /// "Expires" (or "Max-Age") field and consequently is typically stored as a
    /// "session cookie" and thus saved only until the browser quits.
    ///
    /// Note that this does *not* limit the validity duration of the session
    /// key. All issued session keys are valid as long as the persistent secret
    /// is unchanged. There is no mechanism to invalidate individual sessions.
    pub cookie_expires: Option<std::time::Duration>,
}

impl<'a> Default for AuthConfig<'a> {
    fn default() -> Self {
        Self {
            cookie_name: env!["CARGO_PKG_NAME"],
            persistent_secret: Key::generate(),
            token_config: None,
            cookie_expires: None,
        }
    }
}

impl<'a> AuthConfig<'a> {
    /// Convert [Self] to an [AuthLayer].
    pub fn into_layer(self) -> AuthLayer {
        let access_info = AccessInfo::new(self);
        AuthLayer { access_info }
    }
}

#[derive(Clone)]
struct AccessInfo {
    cookie_name: String,
    token_config: Option<TokenConfig>,
    cookie_expires: Option<std::time::Duration>,
    key: tower_cookies::Key,
}

impl AccessInfo {
    /// Generate a random token if needed and return access control information.
    fn new(cfg: AuthConfig<'_>) -> Self {
        let AuthConfig {
            cookie_name,
            persistent_secret,
            token_config,
            cookie_expires,
        } = cfg;

        let key = persistent_secret;

        Self {
            cookie_name: cookie_name.into(),
            token_config,
            key,
            cookie_expires,
        }
    }

    fn check_token_and_cookie(
        &self,
        req: &Request,
        valid_session_key: Option<SessionKey>,
    ) -> Result<(bool, SessionKey), ValidationErrors> {
        let mut errors = Vec::new();

        // First check for token in URI.
        let has_valid_token = self
            .token_config
            .as_ref()
            .map(|i| i.parse_token_from_uri_query(req))
            .unwrap_or(true);

        match (has_valid_token, valid_session_key) {
            (false, None) => {
                errors.push("No (valid) token in uri and no (valid) session.".into());
                Err(ValidationErrors(errors))
            }
            (true, None) => Ok((true, SessionKey::default())),
            (_has_valid_token, Some(session_key)) => Ok((false, session_key)),
        }
    }
}

impl<S> FromRequestParts<S> for SessionKey
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(session_key) = parts.extensions.remove::<SessionKey>() {
            Ok(session_key.clone())
        } else {
            Err((StatusCode::UNAUTHORIZED, "(valid) session key is missing"))
        }
    }
}

/// Implements [Layer] for [AuthMiddleware]
///
/// See the crate-level documentation for an overview.
#[derive(Clone)]
pub struct AuthLayer {
    access_info: AccessInfo,
}

impl<S> Layer<S> for AuthLayer {
    type Service = tower_cookies::CookieManager<AuthMiddleware<S>>;

    fn layer(&self, inner: S) -> Self::Service {
        let auth_middleware = AuthMiddleware {
            inner,
            access_info: self.access_info.clone(),
        };
        tower_cookies::CookieManager::new(auth_middleware)
    }
}

/// Middleware which checks if request is authenticated and, if so, extends the
/// request to include [SessionKey] information.
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    access_info: AccessInfo,
}

impl<S> Service<Request> for AuthMiddleware<S>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(r) => Poll::Ready(r.map_err(Into::into)),
        }
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let Some(cookies) = request
            .extensions()
            .get::<tower_cookies::Cookies>()
            .cloned()
        else {
            // In practice this should never happen because we wrap `CookieManager`
            // directly.
            tracing::error!("missing cookies request extension");
            return Box::pin(std::future::ready(Err(Box::new(ValidationErrors(vec![
                "missing cookies request extension".into(),
            ])) as BoxError)));
        };
        let signed = cookies.signed(&self.access_info.key);

        let err_info = {
            let opt_session_key: Option<SessionKey> = signed
                .get(&self.access_info.cookie_name)
                .map(|received_cookie| {
                    SessionKey(uuid::Uuid::parse_str(received_cookie.value()).unwrap())
                });

            // check if authenticated
            match self
                .access_info
                .check_token_and_cookie(&request, opt_session_key)
            {
                Ok((new_cookie_value, session_key)) => {
                    let expires = self.access_info.cookie_expires.as_ref().map(|exp| {
                        OffsetDateTime::now_utc()
                            .checked_add(Duration::try_from(*exp).unwrap())
                            .unwrap()
                    });

                    request.extensions_mut().insert(session_key.clone());
                    if new_cookie_value {
                        let value = format!("{}", session_key.0.as_hyphenated());
                        let mut set_cookie =
                            tower_cookies::Cookie::new(self.access_info.cookie_name.clone(), value);

                        if let Some(expires) = expires {
                            set_cookie.set_expires(expires);
                        }

                        signed.add(set_cookie);
                    }
                    None
                }
                Err(val_err) => Some(val_err),
            }
        };

        // Build future which generates response.
        let fut = match err_info {
            None => self.inner.call(request),
            Some(val_err) => {
                return Box::pin(std::future::ready(Err(val_err.into())));
            }
        };

        // Await future.
        Box::pin(async move {
            let response: Response = fut.await.map_err(|e| e.into())?;
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use axum::body::Body;
    use cookie::Cookie;
    use http::{Request, StatusCode};

    use std::convert::Infallible;
    use tower::{ServiceBuilder, ServiceExt};

    async fn handler(_: Request<Body>) -> std::result::Result<Response<Body>, Infallible> {
        Ok(Response::new(Body::empty()))
    }

    fn get_cfg() -> AuthConfig<'static> {
        let token_config = Some(TokenConfig {
            name: "token".into(),
            value: "token_value".into(),
        });
        AuthConfig {
            cookie_name: "auth",
            persistent_secret: Key::generate(),
            token_config,
            cookie_expires: None,
        }
    }

    #[tokio::test]
    async fn fail_without_token_or_cookie() -> Result<()> {
        let auth_layer = get_cfg().into_layer();
        let svc = ServiceBuilder::new().layer(auth_layer).service_fn(handler);

        let req = Request::builder().body(Body::empty())?;
        let res = svc.oneshot(req).await;
        assert!(!res
            .err()
            .unwrap()
            .downcast::<ValidationErrors>()
            .unwrap()
            .errors()
            .collect::<Vec<_>>()
            .is_empty());
        Ok(())
    }

    async fn get_second_response(
        cfg: AuthConfig<'_>,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        let auth_layer = cfg.into_layer();
        let svc = ServiceBuilder::new().layer(auth_layer).service_fn(handler);

        // Make a request to get the cookie.
        let res = svc.clone().oneshot(req).await.unwrap();

        // Extract the cookie
        let cookie = {
            let set_cookie: Vec<_> = res
                .headers()
                .get_all(http::header::SET_COOKIE)
                .iter()
                .collect();
            assert_eq!(set_cookie.len(), 1);
            Cookie::parse(set_cookie[0].to_str()?.to_string())?
        };

        // Now make a new request with the cookie.
        let req2 = Request::builder()
            .header(http::header::COOKIE, cookie.stripped().to_string())
            .body(Body::empty())
            .unwrap();
        let res2 = svc.oneshot(req2).await.unwrap();
        Ok(res2)
    }

    #[tokio::test]
    async fn set_cookie_with_trusted_socket() -> Result<()> {
        let mut cfg = get_cfg();
        cfg.token_config = None;
        let uri = "http://example.com/path";
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();

        let res2 = get_second_response(cfg, req).await?;
        assert_eq!(res2.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn set_cookie_with_valid_token() -> Result<()> {
        let cfg = get_cfg();
        let uri = {
            let x = cfg.token_config.as_ref().unwrap();
            format!("http://example.com/path?{}={}", x.name, x.value)
        };
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();

        let res2 = get_second_response(cfg, req).await?;

        assert_eq!(res2.status(), StatusCode::OK);
        Ok(())
    }
}
