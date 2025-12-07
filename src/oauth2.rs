use axum::{
    Router,
    body::Body,
    extract::{Form, OriginalUri, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::{CookieJar, SignedCookieJar};
use chrono::Utc;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::authorization::{AuthorizationState, SignedCookieJarAuthorized};

use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuthorizationQuery {
    pub(crate) login: Option<String>, // Store the selected user key
    pub(crate) response_type: String,
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) scope: Option<String>,
    pub(crate) state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccessTokenRequest {
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

pub async fn login(
    State(state): State<AppState>,
    original_uri: OriginalUri,
    jar: SignedCookieJar<AppState>,
    Query(params): Query<AuthorizationQuery>,
) -> Result<Html<String>, StatusCode> {
    let templates = &state.templates;

    let html = if jar.is_authorized() {
        templates.render_oauth2_login(state.users.as_ref(), &params)
    } else {
        let show_error = jar.get_authorization_state() == AuthorizationState::CodeIsBad;
        templates.render_authorize_form(original_uri, show_error)
    };

    Ok(Html(html))
}

/// Implement OAuth2 Authorization Code enpoint
///
/// Return user login as code if user is defined in configuration
pub async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizationQuery>,
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

    let login = params.login.unwrap_or("".to_string());

    if login.is_empty() {
        let redirect_uri = format!("{}?error=invalid_request", redirect_uri);
        let msg = "login is required and can't be empty string".to_string();
        return response_302
            .header("Location", redirect_uri)
            .body(Body::from(msg))
            .unwrap();
    }

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
pub fn access_token_error(error: &str) -> Response {
    info!("Access token error: {:?}", error);
    let body = AccessTokenError {
        error: error.to_string(),
    };
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

/// Implement OAuth2 Token endpoint
pub async fn access_token(
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

pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let header_prefix = format!("{} ", &state.authorization_header_prefix).to_string();

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

    let token = &auth_header[header_prefix.len()..]; // Remove "Bearer " prefix

    info!("User info request for token: {}", token);

    if !state.users_info.contains_key(token) {
        info!("Invalid token: {}", token);
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    let user_info = &state.users_info.get(token).unwrap().user_info;
    return (StatusCode::OK, Json(user_info)).into_response();
}
