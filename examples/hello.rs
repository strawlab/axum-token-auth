use axum::{
    Router,
    error_handling::HandleErrorLayer,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
};
use axum_token_auth::{AuthConfig, SessionKey, TokenConfig};

async fn handle_auth_error(err: tower::BoxError) -> (StatusCode, &'static str) {
    match err.downcast::<axum_token_auth::ValidationErrors>() {
        Ok(err) => {
            eprintln!(
                "Validation error(s): {:?}",
                err.errors().collect::<Vec<_>>()
            );
            (StatusCode::UNAUTHORIZED, "Request is not authorized")
        }
        Err(orig_err) => {
            eprintln!("Unhandled internal error: {orig_err}");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
        }
    }
}

async fn user_handler(session_key: SessionKey) -> impl IntoResponse {
    session_key.is_present();
    Html(format!("hello {:?} <a href=\"/\">index</a>", session_key))
}

fn expand_unspecified(ip: std::net::IpAddr) -> anyhow::Result<Vec<std::net::IpAddr>> {
    if ip.is_unspecified() {
        // Get all interfaces if IP is unspecified.
        Ok(if_addrs::get_if_addrs()?
            .iter()
            .filter_map(|x| {
                let this_ip = x.addr.ip();
                // Take only IP addresses from correct family.
                if ip.is_ipv4() == this_ip.is_ipv4() {
                    Some(this_ip)
                } else {
                    None
                }
            })
            .collect())
    } else {
        Ok(vec![ip])
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // listen globally on port 3000
    let http_server_addr = std::net::ToSocketAddrs::to_socket_addrs("0.0.0.0:3000")?
        .next()
        .unwrap();
    println!("Listening at {http_server_addr}");

    // A long lived encryption key which is used to encode and decode the
    // cookies stored by the client. Typically this would be persisted across
    // program invocations.
    let persistent_secret = cookie::Key::generate();

    // Setup our config. `AuthConfig` is `#[non_exhaustive]`, so we build it with
    // `AuthConfig::new` and then set the fields we want rather than with a struct
    // literal.
    let token_config = TokenConfig::new("token");
    let mut cfg = AuthConfig::new(persistent_secret);
    cfg.token_config = Some(token_config.clone());

    // Precompute the address(es) we will advertise.
    let advertised_addrs: Vec<std::net::SocketAddr> = expand_unspecified(http_server_addr.ip())?
        .into_iter()
        .map(|ip| std::net::SocketAddr::new(ip, http_server_addr.port()))
        .collect();

    // Periodically mint a fresh self-expiring token and print it out-of-band.
    //
    // Because tokens are stateless signed values validated against
    // `persistent_secret`, the running middleware needs no update to rotate
    // them: it accepts any unexpired token and old ones expire on their own. We
    // keep a clone of the secret solely to mint tokens via the free-standing
    // `generate_token` (no need to hold on to the whole `AuthConfig`, which is
    // consumed by `into_layer` below). (This rotation is impossible in 0.2.x,
    // where the single accepted token is frozen into the layer at construction
    // time.)
    //
    // Each token is signed with `persistent_secret` and carries its own expiry.
    // Upon successful authentication with one, the middleware sets a signed
    // cookie enabling subsequent authentications without any token.
    let token_secret = cfg.persistent_secret.clone();
    let token_name = token_config.name.clone();
    tokio::spawn(async move {
        // Tokens are valid for 5 minutes but rotated every 2, so a freshly
        // printed token always overlaps the previous one (no gap with no valid
        // token).
        const TTL: std::time::Duration = std::time::Duration::from_secs(5 * 60);
        const ROTATE_EVERY: std::time::Duration = std::time::Duration::from_secs(2 * 60);
        loop {
            let token = axum_token_auth::generate_token(&token_secret, TTL);
            println!("\nNew access token (valid 5 min):");
            for addr in &advertised_addrs {
                println!(" * http://{addr}/?{token_name}={token}");
            }
            tokio::time::sleep(ROTATE_EVERY).await;
        }
    });

    // Setup auth layer.
    let auth_layer = cfg.into_layer();

    // Build our application with a single route.
    let app = Router::new()
        .route(
            "/",
            get(|| async { Html("Hello, World! <a href=\"/user\">user</a>") }),
        )
        .route("/user", get(user_handler))
        .layer(
            tower::ServiceBuilder::new()
                // `auth_layer` will produce an error if the request cannot be authorized
                // so we must handle that.
                .layer(HandleErrorLayer::new(handle_auth_error))
                .layer(auth_layer),
        );

    // run our app
    let listener = tokio::net::TcpListener::bind(http_server_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
