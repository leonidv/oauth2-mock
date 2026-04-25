
use std::{collections::HashMap, sync::Arc};

use axum_extra::extract::cookie::Key;
use uuid::Uuid;

use crate::{configuration::{ApplicationConfiguration, RegisteredUsers, User}, templates::Templates};


#[derive(Debug, Clone)]
pub(crate) struct AppState {
    /// signed cookie key
    pub(crate) key: Key,

    /// access restriction
    pub(crate) access_restricted: bool,

    /// access code
    pub(crate) access_code: String,

    /// login -> code
    pub(crate) authorization_codes: Arc<HashMap<String, String>>,

    /// code -> access_token
    pub(crate) access_tokens: Arc<HashMap<String, String>>,

    /// access_token -> refresh_token
    pub(crate) refresh_tokens: Arc<HashMap<String, String>>,

    /// access_token -> user
    pub(crate) users_info: Arc<HashMap<String, User>>,

    /// users configuration from file
    pub(crate) users: Arc<RegisteredUsers>,

    pub(crate) authorization_header_prefix: String,

    pub(crate) templates: Arc<Templates>,
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
    pub(crate) fn new(app_config: &ApplicationConfiguration, templates: Templates) -> Self {
        let users = RegisteredUsers::new(&app_config.users);
        let authorization_codes = make_uuids_per_key(&users.logins());

        let codes: Vec<String> = authorization_codes
            .values()
            .map(|s| s.to_string())
            .collect();
        let access_tokens = make_uuids_per_key(&codes);
        let refresh_tokens = make_uuids_per_key(&codes);

        let users_info = link_access_token_with_user(&users, &authorization_codes, &access_tokens);

        let key = Key::from(&app_config.access_restriction.sign_key.as_bytes());

        Self {
            key,
            access_restricted: app_config.access_restriction.enabled,
            access_code: (&app_config).access_restriction.code.clone(),
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

