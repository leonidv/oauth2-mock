use axum::Router;
use tokio::signal;

use std::{path::PathBuf, process::exit};

use crate::{authorization, state::AppState};
use clap::Parser;
use tracing::*;

use crate::{
    configuration::{ApplicationConfiguration, ConfigurationOverrides},
    router::setup_router,
    templates::Templates,
};

#[derive(Parser, Debug)]
#[command(name = "oauth2-mock")]
#[command(about = "OAuth2 Mock Authorization Server")]
struct Args {
    /// Path to an optional JSON configuration layer
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Override the configured server host
    #[arg(long, value_name = "HOST")]
    host: Option<String>,

    /// Override the configured server port
    #[arg(long, value_name = "PORT")]
    port: Option<u16>,

    #[command(subcommand)]
    command: Option<CliCommands>,
}

#[derive(Debug, clap::Subcommand)]
enum CliCommands {
    GenerateSignKey,
}

pub(crate) fn setup_app(app_config: &ApplicationConfiguration) -> Router {
    // Load templates
    let templates = Templates::load();

    let state = AppState::new(app_config, templates);
    setup_router(state)
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match &args.command {
        Some(CliCommands::GenerateSignKey) => {
            println!("{}", authorization::generate_sign_key());
            exit(0)
        }
        None => {}
    }

    // Initialize tracing
    tracing_subscriber::fmt::init();

    if cfg!(feature = "devmode") {
        warn!("Running in devmode")
    }

    let overrides = ConfigurationOverrides {
        server_host: args.host,
        server_port: args.port,
    };
    let app_config = match ApplicationConfiguration::load(args.config.as_deref(), &overrides) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load configuration.\n{}", e);
            std::process::exit(1);
        }
    };

    let app = setup_app(&app_config);

    let server_address = app_config.server_address();
    let listener = tokio::net::TcpListener::bind(&server_address).await?;

    let serve = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal());

    info!(
        "OAuth2 Mock Server listening on http://{}:{}",
        &server_address.0, &server_address.1
    );

    if app_config.access_restriction.enabled {
        info!("Access is restricted")
    }

    info!("Registered users:");
    app_config.users.iter().for_each(|u| {
        info!("  -- {} ({})", u.login, u.description);
    });

    serve.await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_configuration_cli_overrides() {
        let args = Args::try_parse_from([
            "oauth2-mock",
            "--config",
            "local.json",
            "--host",
            "127.0.0.1",
            "--port",
            "8080",
        ])
        .unwrap();

        assert_eq!(args.config, Some(PathBuf::from("local.json")));
        assert_eq!(args.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(args.port, Some(8080));
    }

    #[test]
    fn configuration_cli_overrides_are_optional() {
        let args = Args::try_parse_from(["oauth2-mock"]).unwrap();

        assert!(args.config.is_none());
        assert!(args.host.is_none());
        assert!(args.port.is_none());
    }

    #[test]
    fn rejects_invalid_cli_port() {
        let result = Args::try_parse_from(["oauth2-mock", "--port", "not-a-number"]);

        assert!(result.is_err());
    }
}
