use handlebars::Handlebars;
use rust_embed::Embed;
use serde::Serialize;

use crate::{configuration::{User, RegisteredUsers}, AuthorizationCodeRequest};

#[derive(Embed)]
#[folder = "templates/"]
#[include = "*.hbs"]
struct TemplatesFiles;

const CSS_FILE : &str = include_str!("../templates/style.css");

#[derive(Debug, Clone)]
pub struct Templates {
    handlebars: Handlebars<'static>,
}

#[derive(Serialize)]
struct HomeVariables {
    users : Vec<User>,
}

#[derive(Serialize)]
struct LoginVariables {
    users : Vec<User>,
    auth_params : String,
    redirect_uri : String,
}

impl Templates {
   pub fn load() -> Self {
        let handlebars = load_templates().unwrap();
        Self { handlebars }
    }

    pub fn render_home(&self, users : &RegisteredUsers) -> String {
        let mut users =  Vec::from_iter(users.all().iter().map(|v| v.clone()));
        users.sort_by(|a,b| a.login.cmp(&b.login));
        let data = HomeVariables {users};
        self.handlebars.render("home.hbs", &data).unwrap()
    }

    pub fn render_login(&self, users : &RegisteredUsers, auth_request : &AuthorizationCodeRequest) -> String {
        let mut users =  Vec::from_iter(users.all().iter().map(|v| v.clone()));
        users.sort_by(|a,b| a.login.cmp(&b.login));
        let auth_params = format!("response_type={}&client_id={}&redirect_uri={}{}{}", 
            auth_request.response_type,
            auth_request.client_id,
            auth_request.redirect_uri,
            auth_request.scope.as_ref().map_or("".to_string(), |s| format!("&scope={}",s)),
            auth_request.state.as_ref().map_or("".to_string(), |s| format!("&state={}",s))
        );
        let redirect_uri = auth_request.redirect_uri.clone();
        let  data = LoginVariables {
            users,
            auth_params,
            redirect_uri
        };
        self.handlebars.render("login.hbs", &data).unwrap()
    }

    pub fn css(&self) -> &str {
        return CSS_FILE
    }
}

fn load_templates() -> Result<Handlebars<'static>, Box<dyn std::error::Error>> {
   let mut hbs = Handlebars::new();
   hbs.register_embed_templates::<TemplatesFiles>()?;
   Ok(hbs)
}