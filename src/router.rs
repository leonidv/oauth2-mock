use std::time::Duration;

use tower_http::timeout::TimeoutLayer;

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

use crate::{authorization, oauth2, state::AppState};

use crate::authorization::*;

pub(crate) const CHECK_ACCESS_CODE_PATH: &str = "/check_code";
pub(crate) const OAUTH2_AUTHORIZATION_PATH: &str = "/authorize";

pub fn setup_router(state: AppState) -> Router {
    let authorization_path = state.authorization_path.clone();
    let token_path = state.token_path.clone();
    let userinfo_path = state.userinfo_path.clone();

    let mut router = Router::new()
        .route("/style.css", get(css_styles))
        .route("/", get(home))
        .route("/test", get(login))
        .route(&authorization_path, get(oauth2::login))
        .route(CHECK_ACCESS_CODE_PATH, post(authorization::check_access))
        .route(&token_path, post(oauth2::access_token))
        .route(&userinfo_path, get(oauth2::userinfo));

    // Keep the original direct authorization action for compatibility unless the
    // configured public authorization endpoint uses the same path.
    if authorization_path != OAUTH2_AUTHORIZATION_PATH {
        router = router.route(
            OAUTH2_AUTHORIZATION_PATH,
            get(oauth2::authorize).layer(from_extractor_with_state::<CheckAccessCode, AppState>(
                state.clone(),
            )),
        );
    }

    router
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_millis(100),
        ))
        .with_state(state)
}

async fn home(State(state): State<AppState>) -> Result<Html<String>, StatusCode> {
    let templates = &state.templates;

    let html = templates.render_home(
        &state.users,
        &state.oauth2_name,
        &state.authorization_path,
        &state.token_path,
        &state.userinfo_path,
        &state.authorization_header_prefix,
    );

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
