use axum::Router;
use tokio::signal;

use std::process::exit;

use clap::Parser;
use crate::{authorization, state::AppState};
use tracing::*;

use crate::{
    configuration::ApplicationConfiguration, router::setup_router, templates::Templates
};


#[derive(Parser, Debug)]
#[command(name = "oauth2-mock")]
#[command(about = "OAuth2 Mock Authorization Server")]
struct Args {
    /// Path to the TOML configuration file containing user definitions
    #[arg(short, long)]
    config: Option<String>,

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

    let state = AppState::new(&app_config, templates);
    setup_router(state)
}

pub async  fn run() -> Result<(), Box<dyn std::error::Error>> {
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

    let app_config = match &args.config {
        Some(path) => match ApplicationConfiguration::from_file(path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Failed to load configuration.\n{}", e);
                std::process::exit(1);
            }
        },
        None => ApplicationConfiguration::default(),
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
