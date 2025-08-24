mod configuration;
mod templates;

use axum::{
    Router,
    body::Body,
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
};
use chrono::{Duration, Utc};
use clap::{Parser, builder::Str};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};
use uuid::Uuid;

use configuration::*;
use templates::Templates;

#[derive(Parser, Debug)]
#[command(name = "oauth2-mock")]
#[command(about = "OAuth2 Mock Authorization Server")]
struct Args {
    /// Path to the TOML configuration file containing user definitions
    #[arg(short, long, default_value = "config/application.json")]
    config: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizationCodeRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    login: Option<String>, // Store the selected user key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessTokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: Option<String>,
    client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessTokenError {
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizationCode {
    code: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    expires_at: chrono::DateTime<Utc>,
    user: User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessToken {
    token: String,
    client_id: String,
    scope: Option<String>,
    expires_at: chrono::DateTime<Utc>,
    user_id: String,
    user_key: Option<String>, // Store the user key for lookup
}

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
    fn new(app_config: ApplicationConfiguration, templates: Templates) -> Self {
        let users = RegisteredUsers::new(app_config.users);
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

    // Parse command line arguments
    let args = Args::parse();

    // Load user configuration
    let app_config = ApplicationConfiguration::from_file(&args.config)?;

    // Load templates
    let templates = Templates::load();

    let state = AppState::new(app_config, templates);

    // Build our application with a route
    let app = Router::new()
        .route("/", get(home))
        .route("/authorize", get(authorize))
        .route("/access_token", post(access_token))
        .route("/user_info", get(userinfo))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    info!("OAuth2 Mock Server listening on http://127.0.0.1:3000");
    info!("Available endpoints:");
    info!("  - GET  /authorize - Authorization endpoint");
    info!("  - POST /access_token - Token endpoint");
    info!("  - GET  /user_info - User info endpoint");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn home(
    State(state): State<AppState>,
    Query(params): Query<AuthorizationCodeRequest>,
) -> Result<Html<String>, StatusCode> {
    let templates = &state.templates;

    let html = templates.render_home(state.users.as_ref(), &params);

    Ok(Html(html))
}

/// Implement OAuth2 Authorization Code enpoint
///
/// Return user login as code if user is defined in configuration
async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizationCodeRequest>,
) -> Response {
    info!("Authorization request: {:?}", params);

    if params.client_id.is_empty() {
        let msg = format!("client_id is required and can't be empty string");
        warn!(msg);
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    if params.redirect_uri.is_empty() {
        let msg = format!("redirect_uri is required and can't be empty string");
        warn!(msg);
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    let redirect_uri = params.redirect_uri;

    let parsed_redirect_uri = url::Url::parse(&redirect_uri);
    if parsed_redirect_uri.is_err() {
        let msg = format!(
            "Invalid redirect_uri: {}. Redirect URLs must be valid URLs.",
            redirect_uri
        );
        warn!(msg);
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    let mut parsed_redirect_uri = parsed_redirect_uri.unwrap();

    let response_302 = Response::builder().status(StatusCode::FOUND);

    // Validate required parameters
    if params.response_type != "code" {
        let redirect_uri = format!("{}?error=unsupported_response_type", redirect_uri);
        let msg = format!(
            "Invalid response_type: {}. Only code is allowed",
            params.response_type
        );
        warn!(msg);
        return response_302
            .header("Location", redirect_uri)
            .body(Body::from(msg))
            .unwrap();
    }

    if params.login.clone().unwrap_or("".to_string()).is_empty() {
        let redirect_uri = format!("{}?error=invalid_request", redirect_uri);
        let msg = "login is required and can't be empty string".to_string();
        return response_302
            .header("Location", redirect_uri)
            .body(Body::from(msg))
            .unwrap();
    }

    let login = params.login.unwrap();
    if !state.users.contains_login(&login) {
        let redirect_uri = format!("{}?error=access_denied", redirect_uri);
        let msg = format!("User {} not found", login);
        warn!(msg);
        return response_302
            .header("Location", redirect_uri)
            .body(Body::from(msg))
            .unwrap();
    }

    let code = state.authorization_codes.get(&login).unwrap();
    parsed_redirect_uri
        .query_pairs_mut()
        .append_pair("code", &code);

    if let Some(state) = params.state {
        parsed_redirect_uri
            .query_pairs_mut()
            .append_pair("state", &state);
    }

    response_302
        .header("Location", parsed_redirect_uri.to_string())
        .body(Body::empty())
        .unwrap()
}

/// Generate access token error with BAD_REQUEST status code
fn access_token_error(error: &str) -> Response {
    info!("Access token error: {:?}", error);
    let body = AccessTokenError {
        error: error.to_string(),
    };
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

/// Implement OAuth2 Token endpoint
async fn access_token(
    State(state): State<AppState>,
    Form(token_request): Form<AccessTokenRequest>,
) -> Response {
    info!("Token request: {:?}", token_request);

    if token_request.grant_type.as_str() != "authorization_code" {
        return access_token_error("unsupported_grant_type");
    }

    // Handle authorization code flow
    let code = token_request.code;

    if !state.access_tokens.contains_key(&code) {
        info!("Authorization code not found: {}", code);
        return access_token_error("invalid_grant");
    }

    let access_token = state.access_tokens.get(&code).unwrap();
    let refresh_token = state.refresh_tokens.get(&code).unwrap();

    let body = AccessTokenResponse {
        access_token: access_token.clone(),
        token_type: "bearer".to_string(),
        expires_in: 3600,
        refresh_token: refresh_token.clone(),
    };
    return (StatusCode::OK, Json(body)).into_response();
}

async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let header_prefix = format!("{} ",&state.authorization_header_prefix).to_string();

    // Extract Bearer token from Authorization header
    if !headers.contains_key("authorization") {
        return (StatusCode::BAD_REQUEST, "Require authorization header").into_response();
    }

    let auth_header = headers.get("authorization").and_then(|h| h.to_str().ok());
    if auth_header.is_none() {
        let msg = "Invalid authorization header format (contains non-ASCII symbols)";
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    let auth_header = auth_header.unwrap();

    if !auth_header.starts_with(&header_prefix) {
        let msg = format!(
            "Authorization header must starts with '{}'. 
             You can change prefix in the application config",
            header_prefix
        );
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    let token = &auth_header[header_prefix.len()..]  ; // Remove "Bearer " prefix

    info!("User info request for token: {}", token);

    if !state.users_info.contains_key(token) {
        info!("Invalid token: {}", token);
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    let user_info = &state.users_info.get(token).unwrap().user_info;
    return (StatusCode::OK, Json(user_info)).into_response();
}
