mod configuration;
mod templates;

use axum::{
    body::Body, extract::{Form, Query, State}, http::{HeaderMap, StatusCode}, response::{Html, IntoResponse, Json, Response}, routing::{get, post}, Router
};
use chrono::{Duration, Utc};
use clap::Parser;
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
    #[arg(short, long, default_value = "config/users.json")]
    config: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizationRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    login: Option<String>, // Store the selected user key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

// For form-encoded requests
#[derive(Debug, Clone, Deserialize)]
struct TokenFormRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
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
    user : User,
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
    authorization_codes: Arc<RwLock<HashMap<String, AuthorizationCode>>>,
    access_tokens: Arc<RwLock<HashMap<String, AccessToken>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, String>>>,
    user_config: Arc<UserConfiguration>,
    templates: Arc<Templates>,
}

impl AppState {
    fn new(user_config: UserConfiguration, templates: Templates) -> Self {
        Self {
            authorization_codes: Arc::new(RwLock::new(HashMap::new())),
            access_tokens: Arc::new(RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
            user_config: Arc::new(user_config),
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
    let user_config = UserConfiguration::from_file(&args.config)?;

    // Load templates
    let templates = Templates::load();

    let state = AppState::new(user_config, templates);

    // Build our application with a route
    let app = Router::new()
        .route("/", get(home))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .route(
            "/.well-known/openid_configuration",
            get(openid_configuration),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    info!("OAuth2 Mock Server listening on http://127.0.0.1:3000");
    info!("Available endpoints:");
    info!("  - GET  /authorize - Authorization endpoint");
    info!("  - POST /token - Token endpoint");
    info!("  - GET  /userinfo - User info endpoint");
    info!("  - GET  /.well-known/openid_configuration - OpenID Connect configuration");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn home(
    State(state): State<AppState>,
    Query(params): Query<AuthorizationRequest>,
) -> Result<Html<String>, StatusCode> {
    let templates = &state.templates;

    let html = templates.render_home(state.user_config.as_ref(), &params);

    Ok(Html(html))
}

async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizationRequest>,
) -> Response {

    info!("Authorization request: {:?}", params);

    if params.client_id.is_empty() {
        let msg = format!("client_id is required and can't be empty string");
        warn!(msg);
        return (StatusCode::BAD_REQUEST,msg).into_response();
    }


    if params.redirect_uri.is_empty() {
        let msg = format!("redirect_uri is required and can't be empty string");
        warn!(msg);
        return (StatusCode::BAD_REQUEST,msg).into_response();
    }

    let redirect_uri = params.redirect_uri;

    let parsed_redirect_uri = url::Url::parse(&redirect_uri);
    if parsed_redirect_uri.is_err() {
        let msg = format!("Invalid redirect_uri: {}. Redirect URLs must be valid URLs.",redirect_uri);
        warn!(msg);
        return (StatusCode::BAD_REQUEST,msg).into_response();
    }
    let mut parsed_redirect_uri = parsed_redirect_uri.unwrap();


    let response_302 = Response::builder()
        .status(StatusCode::FOUND);

    // Validate required parameters
    if params.response_type != "code" {
        let redirect_uri = format!("{}?error=unsupported_response_type", redirect_uri);
        let msg = format!("Invalid response_type: {}. Only code is allowed", params.response_type);
        warn!(msg);
        return response_302
                .header("Location", redirect_uri)
                .body(Body::from(msg)).unwrap();
    }

    if params.login.clone().unwrap_or("".to_string()).is_empty() {
        let redirect_uri = format!("{}?error=invalid_request", redirect_uri);
        let msg =  "login is required and can't be empty string".to_string();
        return response_302
                .header("Location", redirect_uri)
                .body(Body::from(msg)).unwrap();
    }

    let login = params.login.unwrap();
    if !state.user_config.users.contains_key(login.as_str()) {
        let redirect_uri = format!("{}?error=access_denied",redirect_uri);
        let msg = format!("User {} not found", login);
        warn!(msg);
        return response_302
                .header("Location", redirect_uri)
                .body(Body::from(msg)).unwrap();
    }

    parsed_redirect_uri.query_pairs_mut().append_pair("code", &login);

    if let Some(state) = params.state {
        parsed_redirect_uri.query_pairs_mut().append_pair("state", &state);
    }

    response_302
        .header("Location", parsed_redirect_uri.to_string())
        .body(Body::empty())
        .unwrap()
 
}

async fn token(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Form(token_request): Form<TokenFormRequest>,
) -> Result<Json<TokenResponse>, StatusCode> {
    info!("Token request: {:?}", token_request);

    match token_request.grant_type.as_str() {
        "authorization_code" => {
            // Handle authorization code flow
            let code = token_request.code.ok_or(StatusCode::BAD_REQUEST)?;

            // Retrieve the authorization code to get the selected user
            let selected_user = {
                let codes = state.authorization_codes.read().await;
                if let Some(auth_code) = codes.get(&code) {
                    Some(auth_code.user.clone())
                } else {
                    None
                }
            };

            // In a real implementation, you would validate the code against stored codes
            // For this mock, we'll accept any code and generate a new token

            let access_token = Uuid::new_v4().to_string();
            let refresh_token = Uuid::new_v4().to_string();

            // Store the access token (in a real app, this would be in a database)
            let access_token_data = AccessToken {
                token: access_token.clone(),
                client_id: token_request
                    .client_id
                    .unwrap_or_else(|| "mock_client".to_string()),
                scope: token_request.redirect_uri.map(|_| "read write".to_string()),
                expires_at: Utc::now() + Duration::hours(1),
                user_id: "mock_user".to_string(),
                user_key: selected_user.map(|u| u.login),
            };

            {
                let mut tokens = state.access_tokens.write().await;
                tokens.insert(access_token.clone(), access_token_data);
            }

            {
                let mut refresh_tokens = state.refresh_tokens.write().await;
                refresh_tokens.insert(refresh_token.clone(), access_token.clone());
            }

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: 3600,
                refresh_token: Some(refresh_token),
                scope: Some("read write".to_string()),
            }))
        }
        "refresh_token" => {
            // Handle refresh token flow
            let _refresh_token = token_request.refresh_token.ok_or(StatusCode::BAD_REQUEST)?;

            // In a real implementation, you would validate the refresh token
            // For this mock, we'll generate a new access token

            let access_token = Uuid::new_v4().to_string();

            let access_token_data = AccessToken {
                token: access_token.clone(),
                client_id: token_request
                    .client_id
                    .unwrap_or_else(|| "mock_client".to_string()),
                scope: Some("read write".to_string()),
                expires_at: Utc::now() + Duration::hours(1),
                user_id: "mock_user".to_string(),
                user_key: None, // For now, we'll use the first user
            };

            {
                let mut tokens = state.access_tokens.write().await;
                tokens.insert(access_token.clone(), access_token_data);
            }

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: 3600,
                refresh_token: None,
                scope: Some("read write".to_string()),
            }))
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<User>, StatusCode> {
    // Extract Bearer token from Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = &auth_header[7..]; // Remove "Bearer " prefix

    info!("User info request for token: {}", token);

    // In a real implementation, you would validate the token and look up the user
    // For this mock, we'll return the first user from configuration or a default
    let user_config = &state.user_config;

    // Try to find the token in our storage to get the user_key
    let access_tokens = state.access_tokens.read().await;
    let user_key = if let Some(access_token) = access_tokens.get(token) {
        access_token.user_key.clone()
    } else {
        None
    };
    drop(access_tokens); // Release the lock

    // If we have a user_key, try to find that user
    if let Some(user_key) = user_key {
        if let Some(user) = user_config.users.get(&user_key) {
            return Ok(Json(user.clone()));
        }
    }

    // Fallback to first user or default
    if let Some((_, user)) = user_config.users.iter().next() {
        // Return the first configured user's claims
        Ok(Json(user.clone()))
    } else {
        // Return default claims if no users are configured
        let default_claims = serde_json::json!({
            "sub": "mock_user_123",
            "name": "Mock User",
            "email": "mock@example.com",
            "email_verified": true,
            "picture": "https://via.placeholder.com/150"
        });

        Ok(Json(User {
            login: "???".to_string(),
            description: "???".to_string(),
            user_info: HashMap::new(),
        }))
    }
}

async fn openid_configuration() -> Json<serde_json::Value> {
    let config = serde_json::json!({
        "issuer": "http://127.0.0.1:3000",
        "authorization_endpoint": "http://127.0.0.1:3000/authorize",
        "token_endpoint": "http://127.0.0.1:3000/token",
        "userinfo_endpoint": "http://127.0.0.1:3000/userinfo",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "name", "email", "email_verified", "picture"]
    });

    Json(config)
}
