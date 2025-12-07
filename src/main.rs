mod authorization;
mod configuration;
mod oauth2;
mod templates;

use axum::{
    Router,
    extract::{Form, OriginalUri, Query, State},
    handler::Handler,
    http::{
        StatusCode,
        header::{self, SET_COOKIE},
    },
    middleware::from_extractor,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use authorization::CookieJarAuthorized;
use configuration::*;
use templates::Templates;

use crate::{authorization::CheckAccessCode, oauth2::authorize};

#[derive(Parser, Debug)]
#[command(name = "oauth2-mock")]
#[command(about = "OAuth2 Mock Authorization Server")]
struct Args {
    /// Path to the TOML configuration file containing user definitions
    #[arg(short, long)]
    config: Option<String>,
}

const CHECK_ACCESS_CODE_PATH: &str = "/check_code";
const OAUTH2_LOGIN_PATH: &str = "/login";
const OAUTH2_AUTHORIZATION_PATH: &str = "/authorize";
const OAUTH2_TOKEN_PATH: &str = "/token";
const OAUTH2_USERINFO_PATH: &str = "/userinfo";

#[derive(Debug, Clone)]
struct AppState {
    /// login -> code
    authorization_codes: Arc<HashMap<String, String>>,

    /// code -> access_token
    access_tokens: Arc<HashMap<String, String>>,

    /// access_token -> refresh_token
    refresh_tokens: Arc<HashMap<String, String>>,

    /// access_token -> user
    users_info: Arc<HashMap<String, User>>,

    /// users configuration from file
    users: Arc<RegisteredUsers>,

    authorization_header_prefix: String,

    templates: Arc<Templates>,
}

/// Generates a hash map with UUID as the value for each key
fn make_uuids_per_key(keys: &Vec<String>) -> HashMap<String, String> {
    keys.into_iter()
        .map(|login| {
            let uuid = Uuid::new_v4().to_string();
            (login.clone(), uuid)
        })
        .collect()
}

fn link_access_token_with_user(
    users: &RegisteredUsers,
    authorization_codes: &HashMap<String, String>,
    access_tokens: &HashMap<String, String>,
) -> HashMap<String, User> {
    authorization_codes
        .iter()
        .map(|(login, code)| {
            let user = users.load(login);
            let access_token = access_tokens.get(code).unwrap();
            (access_token.clone(), user.clone())
        })
        .collect()
}

impl AppState {
    fn new(app_config: &ApplicationConfiguration, templates: Templates) -> Self {
        let users = RegisteredUsers::new(&app_config.users);
        let authorization_codes = make_uuids_per_key(&users.logins());

        let codes: Vec<String> = authorization_codes
            .values()
            .map(|s| s.to_string())
            .collect();
        let access_tokens = make_uuids_per_key(&codes);
        let refresh_tokens = make_uuids_per_key(&codes);

        let users_info = link_access_token_with_user(&users, &authorization_codes, &access_tokens);

        Self {
            authorization_codes: Arc::new(authorization_codes),
            access_tokens: Arc::new(access_tokens),
            refresh_tokens: Arc::new(refresh_tokens),
            users_info: Arc::new(users_info),
            users: Arc::new(users),
            authorization_header_prefix: app_config.oauth2.authorization_header_prefix.clone(),
            templates: Arc::new(templates),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    if cfg!(feature = "devmode") {
        warn!("Running in devmode")
    }

    // Parse command line arguments
    let args = Args::parse();

    let app_config = match &args.config {
        Some(path) => match ApplicationConfiguration::from_file(path) {
            Ok(config) => config,
            Err(e) => {
                info!("Failed to load configuration: {}", e);
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
            get(oauth2::authorize).layer(from_extractor::<CheckAccessCode>()),
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
