use axum::{
    Form, 
    extract::{FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{Response, Redirect, IntoResponse},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use serde::Deserialize;

#[derive(PartialEq, Eq)]
pub(crate) enum AuthorizationState {
    NoCode,
    CodeIsBad,
    CodeIsGood,
}

pub(crate) trait CookieJarAuthorized {
    fn is_authorized(&self) -> bool;
    fn get_authorization_state(&self) -> AuthorizationState;
    fn set_authorized(&self, authorized: bool) -> CookieJar;
}

impl CookieJarAuthorized for CookieJar {
    fn is_authorized(&self) -> bool {
        self.get_authorization_state() == AuthorizationState::CodeIsGood
    }

    fn get_authorization_state(&self) -> AuthorizationState {
        match self.get("authorized") {
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

    fn set_authorized(&self, authorized: bool) -> CookieJar {
        let cookie = if authorized {
            Cookie::new("authorized", "yes")
        } else {
            Cookie::new("authorized", "no")
        };
        let next_jar = self.clone();
        next_jar.add(cookie).clone()
    }
}

pub(crate) struct CheckAccessCode;

impl<S> FromRequestParts<S> for CheckAccessCode
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let maybe_cookies = CookieJar::from_request_parts(parts, state).await;
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
pub(crate) async fn check_access(jar: CookieJar, Form(authorize_params): Form<AccessCodeForm>) -> Response {
    let redirect_uri = &authorize_params.return_to;

    let access_code = authorize_params.access_code;

    let response_jar = jar.set_authorized(access_code == "123");

    (response_jar, Redirect::to(redirect_uri)).into_response()
}
