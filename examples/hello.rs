use axum::{
    error_handling::HandleErrorLayer,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Router,
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

    // Setup our config
    let token = TokenConfig::new_token("token");
    let cfg = AuthConfig {
        token_config: Some(token.clone()),
        persistent_secret,
        ..Default::default()
    };
    // Setup auth layer
    let auth_layer = cfg.into_layer();

    // This is the secret that gets communicated out-of-band to enable initial
    // authentication. This should be frequently regenerated. Upon successful
    // authentication with this token, the auth middleware sets an encrypted
    // cookie in the response which enables subsequent authentications without
    // the token.
    println!("Access token {}", token.value);

    // Display where we are listening.
    {
        let ip_addrs = expand_unspecified(http_server_addr.ip())?;
        println!("Predicted URL(s):");
        for ip in ip_addrs.into_iter() {
            let addr = std::net::SocketAddr::new(ip, http_server_addr.port());
            println!(" * http://{}/?{}={}", addr, token.name, token.value);
        }
    }

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
