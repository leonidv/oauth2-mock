use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use chrono::{Duration, Utc};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tera::{Tera, Context};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "oauth2-mock")]
#[command(about = "OAuth2 Mock Authorization Server")]
struct Args {
    /// Path to the TOML configuration file containing user definitions
    #[arg(short, long, default_value = "config/users.toml")]
    config: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthorizationRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    selected_user: Option<String>, // Store the selected user key
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
    code_challenge: Option<String>,
    selected_user: Option<String>, // Store the selected user key
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserConfig {
    login_id: String,
    claims: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserConfiguration {
    users: HashMap<String, UserConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserInfo {
    #[serde(flatten)]
    claims: serde_json::Value,
}

#[derive(Debug, Clone)]
struct AppState {
    authorization_codes: Arc<RwLock<HashMap<String, AuthorizationCode>>>,
    access_tokens: Arc<RwLock<HashMap<String, AccessToken>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, String>>>,
    user_config: Arc<UserConfiguration>,
    templates: Arc<Tera>,
}

impl AppState {
    fn new(user_config: UserConfiguration, templates: Tera) -> Self {
        Self {
            authorization_codes: Arc::new(RwLock::new(HashMap::new())),
            access_tokens: Arc::new(RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
            user_config: Arc::new(user_config),
            templates: Arc::new(templates),
        }
    }
}

fn load_user_config(config_path: &str) -> Result<UserConfiguration, Box<dyn std::error::Error>> {
    if !Path::new(config_path).exists() {
        warn!("Configuration file not found: {}. Using default configuration.", config_path);
        return Ok(UserConfiguration {
            users: HashMap::new(),
        });
    }

    let config_content = fs::read_to_string(config_path)?;
    let user_config: UserConfiguration = toml::from_str(&config_content)?;
    
    info!("Loaded {} users from configuration file: {}", user_config.users.len(), config_path);
    
    Ok(user_config)
}

fn load_templates() -> Result<Tera, Box<dyn std::error::Error>> {
    let templates = Tera::new("templates/**/*.html")?;
    info!("Loaded templates from templates/ directory");
    Ok(templates)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args = Args::parse();
    
    // Load user configuration
    let user_config = load_user_config(&args.config)?;
    
    // Load templates
    let templates = load_templates()?;
    
    let state = AppState::new(user_config, templates);

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build our application with a route
    let app = Router::new()
        .route("/", get(home))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .route("/.well-known/openid_configuration", get(openid_configuration))
        .layer(cors)
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

async fn home(State(state): State<AppState>) -> Result<Html<String>, StatusCode> {
    let mut context = Context::new();
    
    // Generate user list for the home page
    let user_config = &state.user_config;
    let mut user_list = String::new();
    
    if user_config.users.is_empty() {
        user_list = r#"
            <div class="user-item">
                <h4>No Users Configured</h4>
                <p>No users are currently configured. The server will use default mock user data.</p>
            </div>
        "#.to_string();
    } else {
        for (_user_key, user_config) in &user_config.users {
            let name = user_config.claims.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(&user_config.login_id);
            let email = user_config.claims.get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("No email");
            let sub = user_config.claims.get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            
            user_list.push_str(&format!(r#"
                <div class="user-item">
                    <h4>{}</h4>
                    <p><strong>Login ID:</strong> {}</p>
                    <p><strong>Email:</strong> {}</p>
                    <p><strong>Subject:</strong> {}</p>
                </div>
            "#, name, user_config.login_id, email, sub));
        }
    }
    
    context.insert("user_count", &user_config.users.len());
    context.insert("user_list", &user_list);
    
    match state.templates.render("home.html", &context) {
        Ok(html) => Ok(Html(html)),
        Err(e) => {
            warn!("Failed to render home template: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizationRequest>,
) -> Result<Html<String>, StatusCode> {
    info!("Authorization request: {:?}", params);

    // Validate required parameters
    if params.response_type != "code" {
        return Err(StatusCode::BAD_REQUEST);
    }

    if params.client_id.is_empty() || params.redirect_uri.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Generate authorization code
    let code = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(10);

    // Store the authorization code with selected user (in a real app, this would be in a database)
    let auth_code = AuthorizationCode {
        code: code.clone(),
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        scope: params.scope.clone(),
        expires_at,
        code_challenge: params.code_challenge.clone(),
        selected_user: params.selected_user.clone(),
    };
    
    {
        let mut codes = state.authorization_codes.write().await;
        codes.insert(code.clone(), auth_code);
    }
    
    info!("Generated authorization code: {} for user: {:?}", code, params.selected_user);

    // Build redirect URL
    let mut redirect_url = url::Url::parse(&params.redirect_uri).map_err(|_| StatusCode::BAD_REQUEST)?;
    redirect_url.query_pairs_mut().append_pair("code", &code);
    
    if let Some(state) = params.state {
        redirect_url.query_pairs_mut().append_pair("state", &state);
    }

    // Generate user selection HTML
    let user_config = &state.user_config;
    let mut user_options = String::new();
    
    if user_config.users.is_empty() {
        user_options = r#"
            <div class="user-option" id="user-default" onclick="selectUser('default', 'Default Mock User')">
                <h4>Default Mock User</h4>
                <p>No users configured. Using default mock user.</p>
                <p><em>Click to select this user</em></p>
            </div>
        "#.to_string();
    } else {
        for (user_key, user_config) in &user_config.users {
            let name = user_config.claims.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(&user_config.login_id);
            let email = user_config.claims.get("email")
                .and_then(|v| v.as_str())
                .unwrap_or("No email");
            let sub = user_config.claims.get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            
            user_options.push_str(&format!(r#"
                <div class="user-option" id="user-{}" onclick="selectUser('{}', '{}')">
                    <h4>{}</h4>
                    <p><strong>Login ID:</strong> {}</p>
                    <p><strong>Email:</strong> {}</p>
                    <p><strong>Subject:</strong> {}</p>
                    <p><em>Click to select this user</em></p>
                </div>
            "#, user_key, user_key, name, name, user_config.login_id, email, sub));
        }
    }

    let mut context = Context::new();
    context.insert("user_options", &user_options);
    context.insert("authorization_code", &code);
    context.insert("redirect_url", &redirect_url.as_str());
    
    match state.templates.render("authorization.html", &context) {
        Ok(html) => Ok(Html(html)),
        Err(e) => {
            warn!("Failed to render authorization template: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
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
                    auth_code.selected_user.clone()
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
                client_id: token_request.client_id.unwrap_or_else(|| "mock_client".to_string()),
                scope: token_request.redirect_uri.map(|_| "read write".to_string()),
                expires_at: Utc::now() + Duration::hours(1),
                user_id: "mock_user".to_string(),
                user_key: selected_user,
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
                client_id: token_request.client_id.unwrap_or_else(|| "mock_client".to_string()),
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
) -> Result<Json<UserInfo>, StatusCode> {
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
        if let Some(user_config) = user_config.users.get(&user_key) {
            return Ok(Json(UserInfo {
                claims: user_config.claims.clone(),
            }));
        }
    }
    
    // Fallback to first user or default
    if let Some((_, user_config)) = user_config.users.iter().next() {
        // Return the first configured user's claims
        Ok(Json(UserInfo {
            claims: user_config.claims.clone(),
        }))
    } else {
        // Return default claims if no users are configured
        let default_claims = serde_json::json!({
            "sub": "mock_user_123",
            "name": "Mock User",
            "email": "mock@example.com",
            "email_verified": true,
            "picture": "https://via.placeholder.com/150"
        });
        
        Ok(Json(UserInfo {
            claims: default_claims,
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

