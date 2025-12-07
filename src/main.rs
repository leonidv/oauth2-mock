mod application_state;
mod authorization;
mod configuration;
mod oauth2;
mod templates;

use axum::{
    Router,
    extract::{OriginalUri, State},
    http::{
        StatusCode,
        header::{self},
    },
    middleware::from_extractor_with_state,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use std::process::exit;
use tracing::{info, warn};

use application_state::AppState;
use configuration::*;
use templates::Templates;

use crate::authorization::*;

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

const CHECK_ACCESS_CODE_PATH: &str = "/check_code";
const OAUTH2_LOGIN_PATH: &str = "/login";
const OAUTH2_AUTHORIZATION_PATH: &str = "/authorize";
const OAUTH2_TOKEN_PATH: &str = "/token";
const OAUTH2_USERINFO_PATH: &str = "/userinfo";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
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

    // Load templates
    let templates = Templates::load();

    let state = AppState::new(&app_config, templates);
    let app = setup_router(state);

    let server_address = app_config.server_address();
    let listener = tokio::net::TcpListener::bind(&server_address).await?;
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
    axum::serve(listener, app).await?;
    Ok(())
}

fn setup_router(state: AppState) -> Router {
    Router::new()
        .route("/style.css", get(css_styles))
        .route("/", get(home))
        .route("/test", get(login))
        .route(OAUTH2_LOGIN_PATH, get(oauth2::login))
        .route(CHECK_ACCESS_CODE_PATH, post(authorization::check_access))
        .route(
            OAUTH2_AUTHORIZATION_PATH,
            get(oauth2::authorize).layer(from_extractor_with_state::<CheckAccessCode, AppState>(
                state.clone(),
            )),
        )
        .route(OAUTH2_TOKEN_PATH, post(oauth2::access_token))
        .route(OAUTH2_USERINFO_PATH, get(oauth2::userinfo))
        .with_state(state)
}

async fn home(State(state): State<AppState>) -> Result<Html<String>, StatusCode> {
    let templates = &state.templates;

    let html = templates.render_home(&state.users);

    Ok(Html(html))
}

async fn login(
    State(state): State<AppState>,
    original_uri: OriginalUri,
) -> Result<Html<String>, StatusCode> {
    let templates = &state.templates;
    let html = templates.render_authorize_form(original_uri, true);
    Ok(Html(html))
}

async fn css_styles(State(state): State<AppState>) -> Response {
    let templates = &state.templates;
    return (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css")],
        templates.css().to_string(),
    )
        .into_response();
}
