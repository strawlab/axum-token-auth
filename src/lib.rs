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
//! trusted (see ["Trusted connection flow", below](#trusted-connection-flow)),
//! authentication occurs without any check.
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
//!    authentication token, minted with [AuthConfig::generate_token]. (For
//!    example, the server prints or shows a QR code containing a URL. The URL
//!    includes the token.) The token is signed with the persistent secret and
//!    carries its own expiry, so the server validates it without storing any
//!    per-token state.
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
//! authentication. The session key is still issued as above. A "trusted
//! connection" is defined by setting [AuthConfig::token_config] to `None`. This
//! is useful when the server is only accessible on a loopback interface.
//!
//! # Trusted networks (overlay VPNs)
//!
//! Where setting [AuthConfig::token_config] to `None` trusts *every* connection,
//! [AuthConfig::trusted_networks] trusts *individual clients* by their network
//! address: a request whose immediate peer address falls in one of the
//! configured ranges is authenticated without a token, just like a trusted
//! connection.
//!
//! This is intended for a server fronted by an authenticated, encrypted overlay
//! network — for example [Tailscale] (whose addresses lie in `100.64.0.0/10`) or
//! a WireGuard subnet — where the overlay has already authenticated the peer, so
//! an application token would be redundant. The peer address is taken from the
//! [`ConnectInfo<SocketAddr>`](axum::extract::ConnectInfo) request extension, so
//! the server must be run with
//! [`into_make_service_with_connect_info`](axum::routing::Router::into_make_service_with_connect_info);
//! if that extension is absent the client is treated as untrusted.
//!
//! Because the address checked is the immediate TCP peer, the configured ranges
//! must **not** be reachable through an intermediate reverse proxy, which would
//! make every client appear to originate from the proxy.
//!
//! [Tailscale]: https://tailscale.com/
//!
//! # Session expiration and renewal
//!
//! Session lifetime is controlled by [AuthConfig::session_expires].
//!
//! If it is `None`, issued sessions never expire on their own: a cookie's
//! signature is valid until the persistent secret is changed, and the cookie is
//! a browser "session cookie" (no `Expires` attribute), saved only until the
//! browser quits. To invalidate every session at once, change the persistent
//! secret.
//!
//! If it is `Some(ttl)`, the issue time plus `ttl` is embedded in the (signed,
//! tamper-proof) cookie and enforced by the server, so an expired cookie stops
//! being accepted even if the client keeps presenting it. The same instant is
//! written to the cookie's browser-side `Expires` attribute. The expiry slides
//! forward whenever a request arrives past the halfway point of the session's
//! lifetime, so a regularly-returning client keeps a valid session indefinitely
//! without ever needing the token again — including past the ~400 day cap
//! browsers place on any single cookie's lifetime. A client that stays away
//! longer than `ttl` must re-authenticate with a token.
//!
//! # Cookie security attributes
//!
//! The session cookie's `Secure`, `HttpOnly`, and `SameSite` attributes are
//! configurable via [AuthConfig::cookie_secure], [AuthConfig::cookie_http_only],
//! and [AuthConfig::cookie_same_site]. The defaults (`HttpOnly` on,
//! `SameSite=Strict`, `Secure` off) are safe for the common loopback/HTTP
//! deployment; set `cookie_secure` to `true` when serving over HTTPS.
//!
//! # Removing the token from the URL after login
//!
//! A token left in the address bar can leak through browser history, bookmarks,
//! or `Referer` headers. When [AuthConfig::strip_token_redirect] is enabled (the
//! default), a top-level browser navigation (a `GET` whose `Accept` header
//! includes `text/html`) that authenticates with a token in the query is
//! answered with a redirect to the same location minus the token parameter. The
//! session cookie is set on that redirect, so the follow-up request is already
//! authenticated and never carries the token. Non-browser clients (which do not
//! send `Accept: text/html`) are served normally, so callers that pass a token
//! on every request are unaffected.
//!
//! # For more extensive needs
//!
//! If this crate does not meet your needs, check
//! [`axum-login`](https://crates.io/crates/axum-login).
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![deny(unreachable_pub)]
#![deny(unused_qualifications)]
#![deny(rust_2018_idioms)]
#![warn(clippy::all)]

use axum::{
    BoxError,
    extract::{ConnectInfo, FromRequestParts, Request},
    http::{Method, StatusCode, header, request::Parts},
    response::Response,
};

use base64::Engine as _;
use cookie::time::{Duration, OffsetDateTime, PrimitiveDateTime};
pub use cookie::{Key, SameSite};
use futures_util::future::BoxFuture;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

type HmacSha256 = Hmac<Sha256>;

/// A CIDR network range — an IP address paired with a prefix length — used to
/// populate [AuthConfig::trusted_networks].
///
/// Parse one from CIDR notation with [`str::parse`]:
///
/// ```
/// use axum_token_auth::CidrBlock;
/// let net: CidrBlock = "100.64.0.0/10".parse().unwrap();
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CidrBlock {
    addr: IpAddr,
    prefix_len: u8,
}

impl CidrBlock {
    /// The network's base address, e.g. the `100.64.0.0` of `100.64.0.0/10`.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length in bits, e.g. the `10` of `100.64.0.0/10`.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether `ip` falls within this network. An IPv4 block never contains an
    /// IPv6 address, and vice versa.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                net.to_bits() & mask == ip.to_bits() & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                net.to_bits() & mask == ip.to_bits() & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for CidrBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// Error returned when a string cannot be parsed as a [`CidrBlock`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CidrParseError;

impl std::fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid CIDR block (expected `address/prefix`)")
    }
}

impl std::error::Error for CidrParseError {}

impl std::str::FromStr for CidrBlock {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, prefix_str) = s.split_once('/').ok_or(CidrParseError)?;
        let addr: IpAddr = addr_str.parse().map_err(|_| CidrParseError)?;
        let prefix_len: u8 = prefix_str.parse().map_err(|_| CidrParseError)?;
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            return Err(CidrParseError);
        }
        Ok(CidrBlock { addr, prefix_len })
    }
}

/// Serialize a [CidrBlock] as its CIDR string (e.g. `"100.64.0.0/10"`), matching
/// the [`FromStr`](std::str::FromStr) representation.
#[cfg(feature = "serde")]
impl serde::Serialize for CidrBlock {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Deserialize a [CidrBlock] from a CIDR string (e.g. `"100.64.0.0/10"`).
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CidrBlock {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = std::borrow::Cow::<'de, str>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Label used to derive the dedicated token-MAC key from the master secret.
/// This domain-separates the token MAC from the key `tower-cookies` uses to
/// sign cookies at the key-derivation level.
const TOKEN_KEY_INFO: &[u8] = b"axum-token-auth/token-mac/v1";

/// Base64 engine used to encode tokens (URL-safe, no padding so the token can
/// be dropped into a URL query parameter unescaped).
const TOKEN_B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Current token wire-format version, carried as the first byte of every token
/// and authenticated by the MAC. A token whose version this build does not
/// recognise is rejected, so the format can evolve later (e.g. a new payload
/// field) without older tokens being silently misinterpreted.
const TOKEN_VERSION: u8 = 1;

/// Derive a dedicated token-MAC key from the master secret via a single-step
/// HMAC KDF: `HMAC-SHA256(master, info)`. The cookie-signing key and this key
/// are derived independently from the master secret, so token MACs and cookie
/// signatures share no key material.
fn token_mac_key(key: &Key) -> [u8; 32] {
    let mut kdf =
        HmacSha256::new_from_slice(key.master()).expect("HMAC accepts keys of any length");
    kdf.update(TOKEN_KEY_INFO);
    let out = kdf.finalize().into_bytes();
    let mut subkey = [0u8; 32];
    subkey.copy_from_slice(&out);
    subkey
}

/// Begin a token MAC over the version byte and expiry, keyed by the derived
/// token-MAC key. The version is authenticated so it cannot be flipped to
/// reinterpret a token under different format rules.
fn token_mac(key: &Key, version: u8, expiry_unix: i64) -> HmacSha256 {
    let mut mac =
        HmacSha256::new_from_slice(&token_mac_key(key)).expect("HMAC accepts keys of any length");
    mac.update(&[version]);
    mac.update(&expiry_unix.to_le_bytes());
    mac
}

/// Create a self-expiring, signed token valid until `expiry`.
///
/// The token is `base64url(version_u8 ‖ expiry_i64_le ‖ HMAC-SHA256(token_mac_key,
/// version ‖ expiry))`, where `token_mac_key` is derived from `key` (see
/// [token_mac_key]). Validation requires only `key` and the current time, so the
/// server stores no per-token state.
fn sign_token(key: &Key, expiry: OffsetDateTime) -> String {
    let expiry_unix = expiry.unix_timestamp();
    let mac = token_mac(key, TOKEN_VERSION, expiry_unix)
        .finalize()
        .into_bytes();
    let mut buf = Vec::with_capacity(1 + 8 + mac.len());
    buf.push(TOKEN_VERSION);
    buf.extend_from_slice(&expiry_unix.to_le_bytes());
    buf.extend_from_slice(&mac);
    TOKEN_B64.encode(buf)
}

/// Verify a token produced by [sign_token]: check the version, the signature (in
/// constant time), and that it has not yet expired relative to `now`.
fn verify_token(key: &Key, token: &str, now: OffsetDateTime) -> bool {
    let Ok(buf) = TOKEN_B64.decode(token) else {
        return false;
    };
    // Layout: version (1 byte) ‖ expiry (8 bytes) ‖ MAC. Split it without any
    // indexing that could panic on a short or truncated token.
    let Some((&version, rest)) = buf.split_first() else {
        return false;
    };
    if version != TOKEN_VERSION {
        return false;
    }
    let Some((expiry_bytes, mac_bytes)) = rest.split_first_chunk::<8>() else {
        return false;
    };
    let expiry_unix = i64::from_le_bytes(*expiry_bytes);

    // Constant-time signature check.
    if token_mac(key, version, expiry_unix)
        .verify_slice(mac_bytes)
        .is_err()
    {
        return false;
    }

    match OffsetDateTime::from_unix_timestamp(expiry_unix) {
        Ok(expiry) => now < expiry,
        Err(_) => false,
    }
}

/// Compute `now + ttl`, saturating at the maximum representable timestamp
/// instead of panicking if `ttl` is absurdly large (or otherwise unrepresentable
/// as a [time::Duration][Duration] or [OffsetDateTime] offset).
fn saturating_expiry(now: OffsetDateTime, ttl: std::time::Duration) -> OffsetDateTime {
    Duration::try_from(ttl)
        .ok()
        .and_then(|ttl| now.checked_add(ttl))
        .unwrap_or_else(|| PrimitiveDateTime::MAX.assume_utc())
}

/// Parse a session cookie value of the form `uuid` or `uuid.expiry_unix`.
///
/// Returns the [SessionKey] and, if present, the embedded server-side expiry.
/// Returns `None` if the value cannot be parsed (e.g. a malformed or truncated
/// cookie), in which case it is treated as if no cookie were present.
fn parse_session_cookie(value: &str) -> Option<(SessionKey, Option<OffsetDateTime>)> {
    let (uuid_str, expiry) = match value.split_once('.') {
        Some((uuid_str, expiry_str)) => {
            let secs: i64 = expiry_str.parse().ok()?;
            (
                uuid_str,
                Some(OffsetDateTime::from_unix_timestamp(secs).ok()?),
            )
        }
        None => (value, None),
    };
    let uuid = uuid::Uuid::parse_str(uuid_str).ok()?;
    Some((SessionKey(uuid), expiry))
}

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
///
/// The token *value* is not stored here. Instead, tokens are self-expiring,
/// signed values minted with [AuthConfig::generate_token] and validated against
/// [AuthConfig::persistent_secret], so the server keeps no per-token state. A
/// token is accepted as long as its signature verifies and it has not yet
/// expired.
#[derive(Clone, Debug)]
pub struct TokenConfig {
    /// The key of the token in the URI query parameters.
    pub name: String,
}

impl TokenConfig {
    /// Create a [TokenConfig] for the given query parameter name.
    pub fn new(name: &str) -> Self {
        Self { name: name.into() }
    }
}

/// Configuration for [AuthLayer] and [AuthMiddleware].
///
/// This struct is `#[non_exhaustive]`, so new fields can be added in future
/// releases without breaking downstream code. Construct it with [AuthConfig::new]
/// (or [Default::default]) and then set the public fields you need rather than
/// with a struct literal.
#[derive(Clone, Debug)]
#[non_exhaustive]
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
    /// The authentication token configuration.
    ///
    /// Set to `None` if the entire connection is trusted (e.g. it is on a
    /// loopback interface). In this case, token checking is disabled but
    /// [SessionKey] is still provided by [AuthMiddleware].
    pub token_config: Option<TokenConfig>,
    /// If set, issued sessions expire this long after they are issued, and the
    /// session is renewed (its expiry slid forward) once it passes the halfway
    /// point of its lifetime.
    ///
    /// The expiry is embedded in the (signed, tamper-proof) cookie and enforced
    /// by the server, so an expired cookie stops being accepted even if the
    /// client keeps presenting it. The cookie's browser-side `Expires`
    /// attribute is set to the same instant on every (re)issue. Because the
    /// expiry slides forward on use, a regularly-returning client keeps a valid
    /// session indefinitely without ever needing the token again — including
    /// past the ~400 day cap browsers place on a single cookie's lifetime.
    ///
    /// If `None`, issued sessions never expire (they remain valid as long as
    /// [Self::persistent_secret] is unchanged) and the cookie is a "session
    /// cookie" with no `Expires` attribute, saved only until the browser quits.
    pub session_expires: Option<std::time::Duration>,
    /// Whether the session cookie is marked `Secure` (sent only over HTTPS).
    ///
    /// Defaults to `false` so the cookie still works over plain HTTP on a
    /// loopback interface, which is a common deployment for this crate. Set to
    /// `true` whenever the server is reached over HTTPS.
    pub cookie_secure: bool,
    /// Whether the session cookie is marked `HttpOnly` (hidden from client-side
    /// JavaScript, mitigating session theft via XSS).
    ///
    /// Defaults to `true`; this crate never needs to read the cookie from JS.
    pub cookie_http_only: bool,
    /// The `SameSite` attribute of the session cookie (CSRF defense).
    ///
    /// Defaults to `Some(SameSite::Strict)`. Use `Some(SameSite::Lax)` if
    /// clients must stay authenticated when following cross-site links into the
    /// app, or `None` to omit the attribute entirely. Note that
    /// `Some(SameSite::None)` implies `Secure` per the cookie specification.
    pub cookie_same_site: Option<SameSite>,
    /// Client networks that are trusted to have already authenticated the peer,
    /// so a request from one is accepted without a token (as if
    /// [Self::token_config] were `None` for that client).
    ///
    /// This is for deployments fronted by a trusted overlay network — e.g.
    /// Tailscale (`100.64.0.0/10`) or a WireGuard subnet — where the overlay
    /// authenticates and encrypts the peer connection, making an application
    /// token redundant. The client's address is taken from the
    /// [`ConnectInfo<SocketAddr>`](axum::extract::ConnectInfo) request
    /// extension, so the server must be run with
    /// [`into_make_service_with_connect_info`] for this to take effect; if the
    /// extension is absent the client is treated as untrusted.
    ///
    /// Defaults to empty (no overlay trust). Note that the address checked is
    /// the immediate TCP peer, so this must not include ranges that could be
    /// spoofed via an intermediate reverse proxy.
    ///
    /// [`into_make_service_with_connect_info`]: axum::routing::Router::into_make_service_with_connect_info
    pub trusted_networks: Vec<CidrBlock>,
    /// When a browser navigation authenticates with a token in the query
    /// string, reply with a redirect to the same location minus the token
    /// parameter, so the token does not linger in the address bar, browser
    /// history, or `Referer` headers.
    ///
    /// Only top-level navigations (a `GET` whose `Accept` header includes
    /// `text/html`) are redirected, so programmatic clients that authenticate
    /// with a token on every request are unaffected. Defaults to `true`.
    pub strip_token_redirect: bool,
}

impl Default for AuthConfig<'_> {
    fn default() -> Self {
        Self {
            cookie_name: env!["CARGO_PKG_NAME"],
            persistent_secret: Key::generate(),
            token_config: None,
            session_expires: None,
            cookie_secure: false,
            cookie_http_only: true,
            cookie_same_site: Some(SameSite::Strict),
            trusted_networks: Vec::new(),
            strip_token_redirect: true,
        }
    }
}

impl AuthConfig<'_> {
    /// Create a configuration with the given persistent secret and the default
    /// value for every other field.
    ///
    /// Because [AuthConfig] is `#[non_exhaustive]`, downstream crates cannot
    /// build it with a struct literal; start here (or from [Default::default])
    /// and set the public fields you need:
    ///
    /// ```
    /// use axum_token_auth::{AuthConfig, Key, TokenConfig};
    /// let mut cfg = AuthConfig::new(Key::generate());
    /// cfg.token_config = Some(TokenConfig::new("token"));
    /// let layer = cfg.into_layer();
    /// ```
    pub fn new(persistent_secret: Key) -> Self {
        Self {
            persistent_secret,
            ..Self::default()
        }
    }

    /// Convert [Self] to an [AuthLayer].
    pub fn into_layer(self) -> AuthLayer {
        let access_info = AccessInfo::new(self);
        AuthLayer { access_info }
    }

    /// Mint a self-expiring authentication token valid for `ttl` from now.
    ///
    /// The returned string is the value to place in the [TokenConfig::name]
    /// query parameter of the initial URL handed to the user out-of-band. It is
    /// signed with [Self::persistent_secret] and carries its own expiry, so the
    /// server validates it without storing anything. Prefer a short `ttl`: a
    /// token only needs to live long enough for the first request, after which
    /// the client holds a session cookie. An absurdly large `ttl` saturates at
    /// the maximum representable expiry rather than panicking.
    pub fn generate_token(&self, ttl: std::time::Duration) -> String {
        generate_token(&self.persistent_secret, ttl)
    }
}

/// Mint a self-expiring authentication token valid for `ttl` from now, signed
/// with `secret`.
///
/// This is the free-standing form of [AuthConfig::generate_token]: a token
/// depends only on the persistent secret, so callers that mint tokens (often on
/// a rotation timer) can do so without building — or cloning — a whole
/// [AuthConfig]. Pass the same [Key] that the [AuthConfig::persistent_secret]
/// driving the [AuthLayer] uses, otherwise the minted token will not validate.
///
/// The returned string is the value to place in the [TokenConfig::name] query
/// parameter of the initial URL handed to the user out-of-band. Prefer a short
/// `ttl`: a token only needs to live long enough for the first request, after
/// which the client holds a session cookie. An absurdly large `ttl` saturates at
/// the maximum representable expiry rather than panicking.
pub fn generate_token(secret: &Key, ttl: std::time::Duration) -> String {
    let expiry = saturating_expiry(OffsetDateTime::now_utc(), ttl);
    sign_token(secret, expiry)
}

/// What the middleware should do with the session cookie for this request.
enum SessionAction {
    /// Issue a brand-new session cookie (authenticated via token or trusted
    /// connection, with no valid existing session).
    Issue(SessionKey),
    /// An existing session is still valid; re-issue the cookie to slide its
    /// expiry forward.
    Renew(SessionKey),
    /// An existing session is still valid and does not need renewing; leave the
    /// cookie untouched.
    Keep(SessionKey),
}

impl SessionAction {
    fn session_key(&self) -> &SessionKey {
        match self {
            SessionAction::Issue(sk) | SessionAction::Renew(sk) | SessionAction::Keep(sk) => sk,
        }
    }
}

#[derive(Clone, Debug)]
struct AccessInfo {
    cookie_name: String,
    token_config: Option<TokenConfig>,
    session_expires: Option<std::time::Duration>,
    cookie_secure: bool,
    cookie_http_only: bool,
    cookie_same_site: Option<SameSite>,
    trusted_networks: Vec<CidrBlock>,
    strip_token_redirect: bool,
    key: Key,
}

impl AccessInfo {
    /// Build access control information from the configuration.
    fn new(cfg: AuthConfig<'_>) -> Self {
        let AuthConfig {
            cookie_name,
            persistent_secret,
            token_config,
            session_expires,
            cookie_secure,
            cookie_http_only,
            cookie_same_site,
            trusted_networks,
            strip_token_redirect,
        } = cfg;

        let key = persistent_secret;

        Self {
            cookie_name: cookie_name.into(),
            token_config,
            key,
            session_expires,
            cookie_secure,
            cookie_http_only,
            cookie_same_site,
            trusted_networks,
            strip_token_redirect,
        }
    }

    /// Whether the request's immediate peer is in a configured trusted overlay
    /// network (see [AuthConfig::trusted_networks]). The peer address is read
    /// from the [`ConnectInfo<SocketAddr>`](ConnectInfo) request extension; if
    /// it is absent the client is treated as untrusted.
    fn is_trusted_client(&self, req: &Request) -> bool {
        if self.trusted_networks.is_empty() {
            return false;
        }
        let Some(ConnectInfo(peer)) = req.extensions().get::<ConnectInfo<SocketAddr>>() else {
            return false;
        };
        let ip: IpAddr = peer.ip();
        self.trusted_networks.iter().any(|net| net.contains(&ip))
    }

    /// Check whether the request carries a valid (signed, unexpired) token, is
    /// from a trusted overlay network, or is exempt because the connection is
    /// trusted (no [TokenConfig]).
    fn check_token(&self, req: &Request, now: OffsetDateTime) -> bool {
        // A peer on a trusted overlay network has already been authenticated by
        // that network, so no token is required.
        if self.is_trusted_client(req) {
            return true;
        }

        let Some(token_config) = self.token_config.as_ref() else {
            // No token configured: the connection is trusted.
            return true;
        };

        let query = req.uri().query().unwrap_or("");
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            if key == token_config.name.as_str() && verify_token(&self.key, &value, now) {
                return true;
            }
        }
        false
    }

    /// If this request is a top-level browser navigation carrying a token in
    /// its query string (and [AuthConfig::strip_token_redirect] is enabled),
    /// return the location to redirect to with the token parameter removed, so
    /// the token does not persist in the address bar, history, or `Referer`.
    /// Returns `None` when no redirect should occur.
    fn token_strip_redirect_location(&self, req: &Request) -> Option<String> {
        if !self.strip_token_redirect || req.method() != Method::GET {
            return None;
        }
        // Only the configured token parameter is stripped; if no token auth is
        // configured there is nothing to strip.
        let token_name = self.token_config.as_ref()?.name.as_str();

        // Restrict to top-level browser navigations so programmatic clients
        // (which authenticate with a token per request) are not redirected.
        let accepts_html = req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|accept| accept.contains("text/html"))
            .unwrap_or(false);
        if !accepts_html {
            return None;
        }

        let uri = req.uri();
        let query = uri.query()?;
        let mut kept = Vec::new();
        let mut had_token = false;
        for pair in query.split('&') {
            let name = pair.split('=').next().unwrap_or("");
            if name == token_name {
                had_token = true;
            } else if !pair.is_empty() {
                kept.push(pair);
            }
        }
        if !had_token {
            return None;
        }

        let path = uri.path();
        // A `Location` without a fragment leaves the original fragment intact in
        // the browser, matching the previous client-side strip behaviour.
        Some(if kept.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{}", kept.join("&"))
        })
    }

    /// Decide what to do for this request given any session cookie it presented.
    fn authenticate(
        &self,
        req: &Request,
        existing: Option<(SessionKey, Option<OffsetDateTime>)>,
        now: OffsetDateTime,
    ) -> Result<SessionAction, ValidationErrors> {
        // Discard an existing session whose embedded expiry has passed. A
        // session with no embedded expiry (a legacy cookie) is always kept.
        let valid_session =
            existing.filter(|&(_, expiry)| expiry.is_none_or(|expiry| now < expiry));

        match valid_session {
            Some((session_key, expiry)) => {
                if self.should_renew(expiry, now) {
                    Ok(SessionAction::Renew(session_key))
                } else {
                    Ok(SessionAction::Keep(session_key))
                }
            }
            None => {
                if self.check_token(req, now) {
                    Ok(SessionAction::Issue(SessionKey::default()))
                } else {
                    Err(ValidationErrors(vec![
                        "No (valid) token in uri and no (valid) session.".into(),
                    ]))
                }
            }
        }
    }

    /// Whether a still-valid session should have its expiry slid forward. We
    /// renew once a session has passed the halfway point of its lifetime, which
    /// keeps a returning client's session alive while avoiding a `Set-Cookie`
    /// on every single request.
    fn should_renew(&self, expiry: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
        let Some(ttl) = self.session_expires else {
            // No server-side expiry configured: nothing to slide.
            return false;
        };
        match expiry {
            // Cookie predates expiry support but we now want one: add it.
            None => true,
            Some(expiry) => {
                let ttl = Duration::try_from(ttl).unwrap_or(Duration::ZERO);
                (expiry - now) * 2 < ttl
            }
        }
    }

    /// Build the cookie value (and matching browser-side expiry) for a session
    /// being issued or renewed now.
    fn build_cookie_value(
        &self,
        session_key: &SessionKey,
        now: OffsetDateTime,
    ) -> (String, Option<OffsetDateTime>) {
        match self.session_expires {
            Some(ttl) => {
                let expiry = saturating_expiry(now, ttl);
                (
                    format!(
                        "{}.{}",
                        session_key.0.as_hyphenated(),
                        expiry.unix_timestamp()
                    ),
                    Some(expiry),
                )
            }
            None => (format!("{}", session_key.0.as_hyphenated()), None),
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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

        // Outcome of the auth check: either authorized (optionally with a
        // redirect that strips the token from the URL) or a validation error.
        let mut redirect_location: Option<String> = None;
        let err_info = {
            let now = OffsetDateTime::now_utc();

            // Read and parse any existing session cookie. A malformed cookie is
            // treated as absent rather than panicking.
            let existing = signed
                .get(&self.access_info.cookie_name)
                .and_then(|received_cookie| parse_session_cookie(received_cookie.value()));

            // check if authenticated
            match self.access_info.authenticate(&request, existing, now) {
                Ok(action) => {
                    let session_key = action.session_key().clone();
                    request.extensions_mut().insert(session_key.clone());

                    if matches!(action, SessionAction::Issue(_) | SessionAction::Renew(_)) {
                        let (value, expires) =
                            self.access_info.build_cookie_value(&session_key, now);
                        let mut set_cookie =
                            tower_cookies::Cookie::new(self.access_info.cookie_name.clone(), value);

                        // Apply the configured cookie security attributes (see
                        // `AuthConfig`). Defaults are HttpOnly, SameSite=Strict,
                        // and Secure off.
                        set_cookie.set_secure(self.access_info.cookie_secure);
                        set_cookie.set_http_only(self.access_info.cookie_http_only);
                        set_cookie.set_same_site(self.access_info.cookie_same_site);

                        if let Some(expires) = expires {
                            set_cookie.set_expires(expires);
                        }

                        signed.add(set_cookie);
                    }

                    // Now that the session cookie is set, redirect a browser
                    // navigation to a token-free URL so the token does not
                    // linger in the address bar, history, or `Referer`.
                    redirect_location = self.access_info.token_strip_redirect_location(&request);
                    None
                }
                Err(val_err) => Some(val_err),
            }
        };

        if let Some(val_err) = err_info {
            return Box::pin(std::future::ready(Err(val_err.into())));
        }

        // Short-circuit with a redirect that drops the token parameter. The
        // outer `CookieManager` still serializes the session cookie set above
        // onto this response, so the redirected request arrives authenticated.
        if let Some(location) = redirect_location {
            let response = Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(header::LOCATION, location)
                .body(axum::body::Body::empty())
                .expect("building a redirect response cannot fail");
            return Box::pin(std::future::ready(Ok(response)));
        }

        // Build future which generates response.
        let fut = self.inner.call(request);

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
        AuthConfig {
            cookie_name: "auth",
            persistent_secret: Key::generate(),
            token_config: Some(TokenConfig::new("token")),
            session_expires: None,
            ..Default::default()
        }
    }

    /// A token valid well into the future for the config's secret.
    fn valid_token_uri(cfg: &AuthConfig<'_>) -> String {
        let name = &cfg.token_config.as_ref().unwrap().name;
        let token = cfg.generate_token(std::time::Duration::from_secs(300));
        format!("http://example.com/path?{name}={token}")
    }

    #[tokio::test]
    async fn fail_without_token_or_cookie() -> Result<()> {
        let auth_layer = get_cfg().into_layer();
        let svc = ServiceBuilder::new().layer(auth_layer).service_fn(handler);

        let req = Request::builder().body(Body::empty())?;
        let res = svc.oneshot(req).await;
        assert!(
            !res.err()
                .unwrap()
                .downcast::<ValidationErrors>()
                .unwrap()
                .errors()
                .collect::<Vec<_>>()
                .is_empty()
        );
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
            let set_cookie: Vec<_> = res.headers().get_all(header::SET_COOKIE).iter().collect();
            assert_eq!(set_cookie.len(), 1);
            Cookie::parse(set_cookie[0].to_str()?.to_string())?
        };

        // Now make a new request with the cookie.
        let req2 = Request::builder()
            .header(header::COOKIE, cookie.stripped().to_string())
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
        let uri = valid_token_uri(&cfg);
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();

        let res2 = get_second_response(cfg, req).await?;

        assert_eq!(res2.status(), StatusCode::OK);
        Ok(())
    }

    /// A session cookie issued by v0.2.x held a bare UUID (no embedded expiry),
    /// signed with the persistent secret. After upgrading to self-expiring
    /// sessions, such a cookie must still authenticate: the persistent secret is
    /// unchanged, so its signature verifies, and a missing embedded expiry is
    /// treated as "never expires" until the session is next renewed. This is the
    /// guarantee that existing in-browser cookies survive the upgrade.
    #[tokio::test]
    async fn legacy_bare_uuid_cookie_is_accepted() -> Result<()> {
        let key = Key::generate();
        let mut cfg = get_cfg();
        cfg.persistent_secret = key.clone();
        // Enabling server-side expiry must not reject the legacy cookie.
        cfg.session_expires = Some(std::time::Duration::from_secs(60 * 60 * 24 * 400));
        let cookie_name = cfg.cookie_name.to_string();

        // Forge exactly what v0.2.x stored: a bare-UUID value signed with the
        // persistent secret, with no embedded expiry.
        let legacy_value = format!("{}", uuid::Uuid::new_v4().as_hyphenated());
        let mut jar = cookie::CookieJar::new();
        jar.signed_mut(&key)
            .add(Cookie::new(cookie_name.clone(), legacy_value));
        let signed = jar.get(&cookie_name).unwrap().stripped().to_string();

        let auth_layer = cfg.into_layer();
        let svc = ServiceBuilder::new().layer(auth_layer).service_fn(handler);

        // No token in the URI: the cookie alone must authenticate.
        let req = Request::builder()
            .uri("http://example.com/path")
            .header(header::COOKIE, signed)
            .body(Body::empty())
            .unwrap();
        let res = svc.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn issued_cookie_is_httponly_and_samesite_strict() -> Result<()> {
        let mut cfg = get_cfg();
        cfg.token_config = None;
        let auth_layer = cfg.into_layer();
        let svc = ServiceBuilder::new().layer(auth_layer).service_fn(handler);

        let req = Request::builder()
            .uri("http://example.com/path")
            .body(Body::empty())
            .unwrap();
        let res = svc.oneshot(req).await.unwrap();

        let set_cookie = res.headers().get(header::SET_COOKIE).unwrap().to_str()?;
        let cookie = Cookie::parse(set_cookie.to_string())?;
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        Ok(())
    }

    #[tokio::test]
    async fn cookie_attributes_are_configurable() -> Result<()> {
        let mut cfg = get_cfg();
        cfg.token_config = None;
        cfg.cookie_secure = true;
        cfg.cookie_http_only = false;
        cfg.cookie_same_site = Some(SameSite::Lax);
        let auth_layer = cfg.into_layer();
        let svc = ServiceBuilder::new().layer(auth_layer).service_fn(handler);

        let req = Request::builder()
            .uri("http://example.com/path")
            .body(Body::empty())
            .unwrap();
        let res = svc.oneshot(req).await.unwrap();

        let set_cookie = res.headers().get(header::SET_COOKIE).unwrap().to_str()?;
        let cookie = Cookie::parse(set_cookie.to_string())?;
        assert_eq!(cookie.secure(), Some(true));
        // `http_only(false)` omits the attribute entirely.
        assert_eq!(cookie.http_only(), None);
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
        Ok(())
    }

    #[tokio::test]
    async fn reject_token_with_wrong_secret() -> Result<()> {
        // A token minted with a different secret must not be accepted.
        let other = get_cfg();
        let uri = valid_token_uri(&other);

        let cfg = get_cfg();
        let auth_layer = cfg.into_layer();
        let svc = ServiceBuilder::new().layer(auth_layer).service_fn(handler);
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let res = svc.oneshot(req).await;
        assert!(res.is_err());
        Ok(())
    }

    #[test]
    fn cidr_block_parse_and_contains() {
        let net: CidrBlock = "100.64.0.0/10".parse().unwrap();
        assert!(net.contains(&"100.64.0.1".parse().unwrap()));
        assert!(net.contains(&"100.127.255.255".parse().unwrap()));
        assert!(!net.contains(&"100.128.0.0".parse().unwrap()));
        assert!(!net.contains(&"10.0.0.1".parse().unwrap()));
        // An IPv4 block never matches an IPv6 peer.
        assert!(!net.contains(&"::1".parse().unwrap()));

        // /0 matches everything of its family; /32 and /128 match one address.
        assert!(
            "0.0.0.0/0"
                .parse::<CidrBlock>()
                .unwrap()
                .contains(&"8.8.8.8".parse().unwrap())
        );
        let host: CidrBlock = "192.168.1.5/32".parse().unwrap();
        assert!(host.contains(&"192.168.1.5".parse().unwrap()));
        assert!(!host.contains(&"192.168.1.6".parse().unwrap()));

        let v6: CidrBlock = "fd00::/8".parse().unwrap();
        assert!(v6.contains(&"fd00::1".parse().unwrap()));
        assert!(!v6.contains(&"fe00::1".parse().unwrap()));

        // Malformed input and out-of-range prefixes are rejected.
        assert!("100.64.0.0".parse::<CidrBlock>().is_err());
        assert!("100.64.0.0/33".parse::<CidrBlock>().is_err());
        assert!("fd00::/129".parse::<CidrBlock>().is_err());
        assert!("nonsense/8".parse::<CidrBlock>().is_err());

        // Accessors expose the parsed address and prefix.
        assert_eq!(net.addr(), "100.64.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(net.prefix_len(), 10);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn cidr_block_serde_roundtrip() {
        let net: CidrBlock = "100.64.0.0/10".parse().unwrap();
        let json = serde_json::to_string(&net).unwrap();
        assert_eq!(json, "\"100.64.0.0/10\"");
        assert_eq!(serde_json::from_str::<CidrBlock>(&json).unwrap(), net);
        // An invalid CIDR string is rejected during deserialization.
        assert!(serde_json::from_str::<CidrBlock>("\"nonsense\"").is_err());
    }

    #[test]
    fn token_roundtrip_signature_and_expiry() {
        let key = Key::generate();
        let now = OffsetDateTime::now_utc();
        let token = sign_token(&key, now + Duration::minutes(5));

        // Valid now, expired later.
        assert!(verify_token(&key, &token, now));
        assert!(!verify_token(&key, &token, now + Duration::minutes(6)));

        // Tampering or a wrong key is rejected.
        assert!(!verify_token(&key, &format!("{token}x"), now));
        assert!(!verify_token(&Key::generate(), &token, now));
        assert!(!verify_token(&key, "not base64!!", now));

        // A token whose version byte is altered is rejected (the version is
        // authenticated and unknown versions are refused).
        let mut bytes = TOKEN_B64.decode(&token).unwrap();
        bytes[0] = bytes[0].wrapping_add(1);
        assert!(!verify_token(&key, &TOKEN_B64.encode(bytes), now));
    }

    #[test]
    fn expiry_saturates_instead_of_panicking() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

        // A normal duration adds as expected.
        let normal = saturating_expiry(now, std::time::Duration::from_secs(60));
        assert_eq!(normal, now + Duration::seconds(60));

        // An absurd duration saturates at the maximum representable timestamp
        // rather than panicking.
        let huge = saturating_expiry(now, std::time::Duration::from_secs(u64::MAX));
        assert_eq!(huge, PrimitiveDateTime::MAX.assume_utc());
    }

    #[test]
    fn session_cookie_parsing() {
        let sk = SessionKey::default();
        let expiry = OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap();

        // Without an embedded expiry.
        let bare = format!("{}", sk.0.as_hyphenated());
        assert_eq!(parse_session_cookie(&bare), Some((sk.clone(), None)));

        // With an embedded expiry.
        let with_exp = format!("{}.{}", sk.0.as_hyphenated(), expiry.unix_timestamp());
        assert_eq!(parse_session_cookie(&with_exp), Some((sk, Some(expiry))));

        // Garbage parses to nothing rather than panicking.
        assert_eq!(parse_session_cookie("nonsense"), None);
        assert_eq!(parse_session_cookie(""), None);
    }

    #[test]
    fn renews_past_halfway_point() {
        let mut cfg = get_cfg();
        cfg.session_expires = Some(std::time::Duration::from_secs(100));
        let access_info = AccessInfo::new(cfg);
        let now = OffsetDateTime::now_utc();

        // 60s left of a 100s lifetime: still in the first half, keep as-is.
        assert!(!access_info.should_renew(Some(now + Duration::seconds(60)), now));
        // 40s left: past halfway, renew.
        assert!(access_info.should_renew(Some(now + Duration::seconds(40)), now));
        // A cookie with no embedded expiry gets one added.
        assert!(access_info.should_renew(None, now));
    }

    /// A client whose peer address is inside a configured trusted overlay
    /// network is authenticated without any token, just like a trusted
    /// (token-less) connection.
    #[tokio::test]
    async fn trusted_network_skips_token() -> Result<()> {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let mut cfg = get_cfg(); // token IS required by default
        cfg.trusted_networks = vec!["100.64.0.0/10".parse().unwrap()];
        let auth_layer = cfg.into_layer();
        let svc = ServiceBuilder::new().layer(auth_layer).service_fn(handler);

        // From inside the overlay range: accepted with no token.
        let mut trusted = Request::builder()
            .uri("http://example.com/path")
            .body(Body::empty())
            .unwrap();
        trusted.extensions_mut().insert(ConnectInfo(
            "100.100.1.2:5555".parse::<SocketAddr>().unwrap(),
        ));
        assert_eq!(
            svc.clone().oneshot(trusted).await.unwrap().status(),
            StatusCode::OK
        );

        // From outside the overlay range with no token: rejected.
        let mut untrusted = Request::builder()
            .uri("http://example.com/path")
            .body(Body::empty())
            .unwrap();
        untrusted.extensions_mut().insert(ConnectInfo(
            "192.168.1.2:5555".parse::<SocketAddr>().unwrap(),
        ));
        assert!(svc.oneshot(untrusted).await.is_err());
        Ok(())
    }

    /// A browser navigation (GET + `Accept: text/html`) that authenticates with
    /// a token in the URL is redirected (303) to the same path with the token
    /// removed, and the session cookie is set on that redirect.
    #[tokio::test]
    async fn browser_token_auth_redirects_without_token() -> Result<()> {
        let cfg = get_cfg();
        // valid_token_uri yields `.../path?token=XXX`; add another parameter so
        // we can assert it survives the strip.
        let uri = format!("{}&keep=1", valid_token_uri(&cfg));
        let auth_layer = cfg.into_layer();
        let svc = ServiceBuilder::new().layer(auth_layer).service_fn(handler);

        let req = Request::builder()
            .uri(uri)
            .header(header::ACCEPT, "text/html,application/xhtml+xml")
            .body(Body::empty())
            .unwrap();
        let res = svc.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers().get(header::LOCATION).unwrap().to_str()?;
        // Token stripped, other query parameters preserved.
        assert_eq!(location, "/path?keep=1");
        // The session cookie is issued on the redirect itself.
        assert!(res.headers().contains_key(header::SET_COOKIE));
        Ok(())
    }

    /// A programmatic client (no `Accept: text/html`) authenticating with a
    /// token is served normally rather than redirected, so non-browser callers
    /// that pass a token per request keep working.
    #[tokio::test]
    async fn programmatic_token_auth_is_not_redirected() -> Result<()> {
        let cfg = get_cfg();
        let uri = valid_token_uri(&cfg);
        let auth_layer = cfg.into_layer();
        let svc = ServiceBuilder::new().layer(auth_layer).service_fn(handler);

        let req = Request::builder()
            .uri(uri)
            .header(header::ACCEPT, "*/*")
            .body(Body::empty())
            .unwrap();
        let res = svc.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        Ok(())
    }
}
