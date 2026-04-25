use axum::{
    Form,
    extract::{FromRef, FromRequestParts, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{
    SignedCookieJar,
    cookie::{Cookie, Key},
};
use rand::distr::{Alphanumeric, SampleString};
use serde::Deserialize;

use crate::state::AppState;
use cookie::time::Duration;

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Key {
        state.key.clone()
    }
}

impl Into<Key> for AppState {
    fn into(self) -> Key {
        self.key.clone()
    }
}

#[derive(PartialEq, Eq)]
pub(crate) enum AuthorizationState {
    NoCode,
    CodeIsBad,
    CodeIsGood,
}

pub(crate) trait SignedCookieJarAuthorized {
    fn is_authorized(&self) -> bool;
    fn get_authorization_state(&self) -> AuthorizationState;
    fn set_authorized(&self, authorized: bool) -> Self;
}

const COOKIE_NAME: &str = "authorized";
impl SignedCookieJarAuthorized for SignedCookieJar<AppState> {
    fn is_authorized(&self) -> bool {
        self.get_authorization_state() == AuthorizationState::CodeIsGood
    }

    fn get_authorization_state(&self) -> AuthorizationState {
        match self.get(COOKIE_NAME) {
            Some(cookie) => {
                if cookie.value() == "yes" {
                    AuthorizationState::CodeIsGood
                } else {
                    AuthorizationState::CodeIsBad
                }
            }
            None => AuthorizationState::NoCode,
        }
    }

    fn set_authorized(&self, authorized: bool) -> Self {
        let yes_no = if authorized { "yes" } else { "no" };
        let cookie = Cookie::build((COOKIE_NAME, yes_no))
            .max_age(Duration::days(365))
            .http_only(true);

        let next_jar = self.clone();
        next_jar.add(cookie).clone()
    }
}

pub(crate) struct CheckAccessCode;

impl FromRequestParts<AppState> for CheckAccessCode {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if !state.access_restricted {
            return Ok(Self);
        }

        let maybe_cookies = SignedCookieJar::from_request_parts(parts, state).await;
        match maybe_cookies {
            Ok(cookies) => {
                if cookies.is_authorized() {
                    Ok(Self)
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            }
            _ => Err(StatusCode::UNAUTHORIZED),
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct AccessCodeForm {
    access_code: String,
    return_to: String,
}

#[axum::debug_handler]
pub(crate) async fn check_access(
    State(state): State<AppState>,
    jar: SignedCookieJar<AppState>,
    Form(authorize_params): Form<AccessCodeForm>,
) -> Response {
    let response_jar = jar.set_authorized(state.access_code == authorize_params.access_code);
    let redirect_uri = &authorize_params.return_to;

    (response_jar, Redirect::to(redirect_uri)).into_response()
}

/// Generate random string for signing cookies
pub fn generate_sign_key() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 64)
}
