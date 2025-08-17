use handlebars::Handlebars;
use rust_embed::Embed;
use serde::Serialize;

use crate::{configuration::{self, User, UserConfiguration}, AuthorizationRequest};

#[derive(Embed)]
#[folder = "templates/"]
#[include = "*.hbs"]
struct TemplatesFiles;

#[derive(Debug, Clone)]
pub struct Templates {
    handlebars: Handlebars<'static>,
}


#[derive(Serialize)]
struct HomeVariables {
    users : Vec<User>,
    auth_params : String,
    redirect_uri : String,
}

impl Templates {
   pub fn load() -> Self {
        let handlebars = load_templates().unwrap();
        Self { handlebars }
    }

    pub fn render_home(&self, configuration : &UserConfiguration, auth_request : &AuthorizationRequest) -> String {
        let mut users =  Vec::from_iter(configuration.users.values().map(|v| v.clone()));
        users.sort_by(|a,b| a.login.cmp(&b.login));
        let auth_params = format!("response_type={}&client_id={}&redirect_uri={}{}{}", 
            auth_request.response_type,
            auth_request.client_id,
            auth_request.redirect_uri,
            auth_request.scope.as_ref().map_or("".to_string(), |s| format!("&scope={}",s)),
            auth_request.state.as_ref().map_or("".to_string(), |s| format!("&state={}",s))
        );
        let redirect_uri = auth_request.redirect_uri.clone();
        let  data = HomeVariables {
            users,
            auth_params,
            redirect_uri
        };
        self.handlebars.render("home.hbs", &data).unwrap()
    }
}

fn load_templates() -> Result<Handlebars<'static>, Box<dyn std::error::Error>> {
   let mut hbs = Handlebars::new();
   hbs.register_embed_templates::<TemplatesFiles>()?;
   Ok(hbs)
}