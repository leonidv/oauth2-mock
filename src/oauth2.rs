use std::rc::Rc;

use axum::{
    body::Body,
    extract::{Form, OriginalUri, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Response},
};
use axum_extra::extract::SignedCookieJar;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::authorization::{AuthorizationState, SignedCookieJarAuthorized};
use crate::state::AppState;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorType {
    AccessCode,
    AccessToken,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct AuthorizationQuery {
    pub(crate) login: Option<String>, // Store the selected user key
    pub(crate) error: Option<String>, // Return error instead of code
    pub(crate) error_type: Option<ErrorType>, // Return error when request access code or access token
    pub(crate) response_type: String,
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) scope: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) previous_state: Option<String>,
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

    let require_access_code = state.access_restricted && !jar.is_authorized();

    let html = if require_access_code {
        let show_error = jar.get_authorization_state() == AuthorizationState::CodeIsBad;
        templates.render_authorize_form(original_uri, show_error)
    } else {
        templates.render_oauth2_login(state.users.as_ref(), &params)
    };

    Ok(Html(html))
}

/// Implement OAuth2 Authorization Code enpoint
///
/// Return user login as code if user is defined in configuration
pub async fn authorize(
    State(app_state): State<AppState>,
    Query(params): Query<AuthorizationQuery>,
) -> Response {
    info!("Authorization request: {:?}", params);

    let params = Rc::new(params);

    let AuthorizationQuery {
        login,
        error,
        error_type,
        response_type,
        client_id,
        redirect_uri,
        scope : _,
        state,
        previous_state:_,
    } = params.as_ref();

    // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
    // Should return 400 BAD_REQUEST for cases:
    // -- invalid or incorrect redirect_uri
    // -- missing client_id
    if client_id.is_empty() {
        let msg = format!("client_id is required and can't be empty string");
        warn!(msg);
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    if redirect_uri.is_empty() {
        let msg = format!("redirect_uri is required and can't be empty string");
        warn!(msg);
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

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

    if let Some(error_type) = error_type {
        // Guard that error is provided
        let error = error.clone().unwrap_or("".to_string());
        if error.is_empty() {
            let msg = "Error MUST be provided or not passed";
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }

                if let ErrorType::AccessCode = error_type {
            return client_error(
                error,
                "Explicit error from oauth2-mock".to_string(),
                params.clone(),
            );
        }

    }

            // Process only access code errors, because access token errors processed as correct response

    // Validate required parameters
    if response_type != "code" {
        let msg = format!(
            "Invalid response_type: {}. Only code is allowed",
            response_type
        );
        return client_error("unsupported_response_type", &msg, params.clone());
    }

    let login = login.clone().unwrap_or("".to_string());

    if login.is_empty() {
        let msg = "login or error is required and can't be empty string";
        return client_error("invalid_request", msg, params.clone());
    }

    if !app_state.users.contains_login(&login) {
        let msg = format!("User {} not found", login);
        return client_error("access_denied", &msg, params.clone());
    }

    let response_302 = Response::builder().status(StatusCode::FOUND);

    let code = if let Some(ErrorType::AccessToken) = error_type {
       error.as_ref().unwrap().to_string()
    } else {
        app_state.authorization_codes.get(&login).unwrap().to_string()
    };

    parsed_redirect_uri
        .query_pairs_mut()
        .append_pair("code", &code);

    if let Some(state) = &state {
        parsed_redirect_uri
            .query_pairs_mut()
            .append_pair("state", state);
    }

    response_302
        .header("Location", parsed_redirect_uri.to_string())
        .body(Body::empty())
        .unwrap()
}

/// Generate client redirect error with provided error
fn client_error<S: Into<String> + std::fmt::Display>(
    error: S,
    error_description: S,
    query: Rc<AuthorizationQuery>,
) -> Response {
    let redirect_uri = &query.redirect_uri;
    let state = query
        .state
        .clone()
        .map_or("".to_string(), |s| format!("&state={}", s));
    let location =
        format!("{redirect_uri}?error={error}&error_description={error_description}{state}");

    info!("{error_description}");

    Response::builder()
        .status(StatusCode::FOUND)
        .header("Location", location)
        .body(Body::empty())
        .unwrap()
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

    if code.starts_with("invalid") || code.starts_with("unauthorized") {
        let body = Body::from(format!("{{ error: \"{code}\" }}"));
        return (StatusCode::BAD_REQUEST, body).into_response();
    };

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

/// Generate access token error with BAD_REQUEST status code
pub fn access_token_error(error: &str) -> Response {
    info!("Access token error: {:?}", error);
    let body = AccessTokenError {
        error: error.to_string(),
    };
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
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
