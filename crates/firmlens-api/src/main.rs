use firmlens_api::{build_router, ensure_loopback_ip, ApiConfig, AppState, DEFAULT_PORT};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .try_init();
}

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();

    let ip: IpAddr = match std::env::var("FIRMLENS_API_HOST") {
        Ok(raw) => match raw.parse::<IpAddr>() {
            Ok(parsed) => parsed,
            Err(e) => {
                eprintln!("error: invalid FIRMLENS_API_HOST '{raw}': {e}");
                return ExitCode::from(1);
            }
        },
        Err(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };

    if let Err(msg) = ensure_loopback_ip(ip) {
        eprintln!("error: {msg}");
        return ExitCode::from(1);
    }

    let port: u16 = match std::env::var("FIRMLENS_API_PORT") {
        Ok(raw) => match raw.parse::<u16>() {
            Ok(p) if p > 0 => p,
            _ => {
                eprintln!("error: invalid FIRMLENS_API_PORT '{raw}'");
                return ExitCode::from(1);
            }
        },
        Err(_) => DEFAULT_PORT,
    };

    let addr = SocketAddr::new(ip, port);
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to bind firmlens-api on {addr}: {e}");
            return ExitCode::from(1);
        }
    };

    let state = AppState::new(ApiConfig::default());
    let app = build_router(state);

    tracing::info!(
        "firmlens-api v{} listening on http://{} (loopback only)",
        firmlens_core::SCANNER_VERSION,
        addr
    );

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("error: firmlens-api server error: {e}");
        return ExitCode::from(1);
    }

    ExitCode::from(0)
}
