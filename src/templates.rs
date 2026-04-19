
use axum::extract::OriginalUri;
use handlebars::{DirectorySourceOptions, Handlebars};
use rust_embed::Embed;
use serde::Serialize;
use tracing::info;

use crate::{
    CHECK_ACCESS_CODE_PATH, configuration::{RegisteredUsers, User}, oauth2::AuthorizationQuery
};

#[derive(Embed)]
#[folder = "templates/"]
#[include = "*.hbs"]
struct TemplatesFiles;

const CSS_FILE: &str = include_str!("../templates/style.css");

#[derive(Debug, Clone)]
pub struct Templates {
    handlebars: Handlebars<'static>,
}

#[derive(Serialize)]
struct HomeVariables {
    users: Vec<User>,
}

#[derive(Serialize)]
struct LoginVariables {
    users: Vec<User>,
    auth_params: String,
    redirect_uri: String,
    state: String,
    state_changed: bool,
    previous_state: String,
}

#[derive(Serialize)]
struct AuthorizeFormVariables {
    action_url: String,
    show_error: bool,
    return_to: String,
}

impl Templates {
    pub fn load() -> Self {
        let handlebars = load_templates().unwrap();
        Self { handlebars }
    }

    pub fn render_home(&self, users: &RegisteredUsers) -> String {
        let mut users = Vec::from_iter(users.all().iter().map(|v| v.clone()));
        users.sort_by(|a, b| a.login.cmp(&b.login));
        let data = HomeVariables { users };
        self.handlebars.render("home", &data).unwrap()
    }

    pub fn render_authorize_form(&self, uri : OriginalUri, show_error : bool) -> String {
        let return_to = uri.0.to_string();
        let data = AuthorizeFormVariables {
            action_url: CHECK_ACCESS_CODE_PATH.to_string(),
            show_error,
            return_to,
        };
        self.handlebars.render("access_code_form", &data).unwrap()
    }

    pub fn render_oauth2_login(
        &self,
        users: &RegisteredUsers,
        auth_request: &AuthorizationQuery,
    ) -> String {
        let mut users = Vec::from_iter(users.all().iter().map(|v| v.clone()));
        users.sort_by(|a, b| a.login.cmp(&b.login));

        let state = auth_request.state.clone();
        let previous_state = auth_request.previous_state.clone();

        let auth_params = format!(
            "response_type={}&client_id={}&redirect_uri={}{}{}",
            auth_request.response_type,
            auth_request.client_id,
            auth_request.redirect_uri,
            auth_request
                .scope
                .as_ref()
                .map_or("".to_string(), |s| format!("&scope={}", s)),
            state
                .clone()
                .map_or("".to_string(), |s| format!("&state={}", s))
        );
        let redirect_uri = auth_request.redirect_uri.clone();
        let data = LoginVariables {
            users,
            auth_params,
            redirect_uri,
            state_changed: previous_state.is_some(),
            state: state.unwrap_or("".to_string()),
            previous_state: previous_state.unwrap_or("".to_string()),
        };
        self.handlebars.render("oauth2_login", &data).unwrap()
    }

    pub fn css(&self) -> &str {
        return CSS_FILE;
    }
}

fn load_templates() -> Result<Handlebars<'static>, Box<dyn std::error::Error>> {
    let mut hbs = Handlebars::new();
    hbs.register_escape_fn(handlebars::no_escape);
    if cfg!(feature = "devmode") {
        info!("devmode: activate templates hot reload");
        hbs.set_dev_mode(true);
        hbs.register_templates_directory("templates/", DirectorySourceOptions::default()).unwrap();
    } else {
        hbs.register_embed_templates_with_extension::<TemplatesFiles>(".hbs")?;
    }

    Ok(hbs)
}

