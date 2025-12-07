use std::{
    collections::HashMap,
    fs,
    path::{self, Path},
};

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::authorization;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Configuration {
    pub authorization_header_prefix: String,
}

/// Network server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfiguration {
    /// Server host.
    /// Use 0.0.0.0 to make it available from all interfaces (useful for running in Docker)
    pub host: String,

    /// Server port
    pub port: u16,
}

/// You can restrict access to the oauth2-mock server by the code.
/// When access restriction is enabled, the user must provide the access code to make OAuth2 authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRestriction {
    /// Enable or disable access restriction
    pub enabled: bool,

    /// Access code, which will be required to make OAuth2 authorization
    pub code: String,

    /// Sign key for signed cookies. Should be more than 64 characters or empty.
    /// If it is empty, a key will be generated automatically. This is not a recommended way
    /// because users will have to enter an access code after each service reboot.
    /// You can run `oauth2mock generate-sign-key` to get valid key.
    pub sign_key: String,
}

/// Users configuration. See [User] struct for more information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredUsers {
    /// Keys are logins, values are users
    users: HashMap<String, User>,
}

/// User configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Login allows identifying a user quickly and meaningfully.
    /// OAuth2 mock property, does not affect OAuth2 authorization
    pub login: String,

    /// Good description allows choose right user for authorization.
    /// OAuth2 mock property, does not affect OAuth2 authorization
    pub description: String,

    /// User info which will be returned by userinfo endpoint
    #[serde(rename = "userInfo")]
    pub user_info: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationConfiguration {
    pub server: ServerConfiguration,
    pub oauth2: OAuth2Configuration,
    pub access_restriction: AccessRestriction,
    pub users: Vec<User>,
}

/// Used to display help message after loading default configuration
const DEFAULT_CONFIG_PATH: &str = "config/application.json";
const DEFAULT_CONFIG: &str = include_str!("../config/application.json");

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigurationError {
    FileNotFound(String),
    CantBuildAbsolutePath(String),
    NoUsers,
    AccessRestrictionError(String),
}

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigurationError::FileNotFound(path) => write!(f, "File not found: {}", path),
            &ConfigurationError::CantBuildAbsolutePath(ref path) => {
                write!(f, "Cant build absolute path: {}", path)
            }
            ConfigurationError::NoUsers => {
                write!(f, "Config must contains list of users")
            }
            &ConfigurationError::AccessRestrictionError(ref message) => {
                write!(f, "Access restriction configuration error: {}", message)
            }
        }
    }
}

impl std::error::Error for ConfigurationError {}

impl RegisteredUsers {
    /// Create a new UserConfiguration from a list of users
    pub fn new(users: &Vec<User>) -> Self {
        Self {
            users: users
                .into_iter()
                .map(|u| (u.login.clone(), u.clone()))
                .collect(),
        }
    }

    /// Return logins of all users
    ///
    /// Make clone of user's keys.
    pub fn logins(&self) -> Vec<String> {
        self.users.keys().into_iter().cloned().collect()
    }

    pub fn contains_login(&self, login: &String) -> bool {
        self.users.contains_key(login)
    }

    /// Find user by login. Return None if user not found
    pub fn find(&self, login: &String) -> Option<&User> {
        self.users.get(login)
    }

    /// Find user by login. Panic if user not found
    /// Use this method only if you are sure that user exists
    pub fn load(&self, login: &String) -> &User {
        self.find(login).unwrap()
    }

    pub fn all(&self) -> Vec<User> {
        self.users.values().cloned().collect()
    }
}

impl ApplicationConfiguration {
    /// Create a application configuration from a JSON string
    fn from_json(json: &str) -> Result<Self, Box<dyn std::error::Error>> {
        match serde_json::from_str::<ApplicationConfiguration>(json) {
            Ok(mut config) => {
                if config.users.is_empty() {
                    return Err(Box::new(ConfigurationError::NoUsers));
                }

                let access_restriction = &config.access_restriction;
                if access_restriction.enabled {
                    if access_restriction.code.is_empty() {
                        return Err(Box::new(ConfigurationError::AccessRestrictionError(
                            "Access restriction is enabled, but code is empty".to_string(),
                        )));
                    }

                    let sign_key_len = access_restriction.sign_key.len();
                    if sign_key_len > 0 && sign_key_len < 64 {
                        return Err(Box::new(ConfigurationError::AccessRestrictionError(
                            "Sign key must be at least 64 characters long".to_string(),
                        )));
                    }
                }

                if !access_restriction.enabled || access_restriction.sign_key.is_empty() {
                    // small hack, even if access restriction disable,
                    // we generate sign key to provide valid sign key in the configuration
                    config.access_restriction.sign_key = authorization::generate_sign_key()
                }

                Ok(config)
            }

            Err(e) => {
                warn!("Failed to parse JSON configuration: {}", e);
                Err(Box::new(e))
            }
        }
    }

    /// Load a user configuration from a file
    pub fn from_file<P: AsRef<Path>>(
        file_name: P,
    ) -> Result<ApplicationConfiguration, Box<dyn std::error::Error>> {
        let absolute_path = path::absolute(file_name.as_ref());

        if absolute_path.is_err() {
            let e = absolute_path.err().unwrap();
            error!(
                "Failed to load configuration file: {}, os_error: {}, error: {},",
                file_name.as_ref().display(),
                e.raw_os_error()
                    .map_or("unknown".to_string(), |e| e.to_string()),
                e.to_string(),
            );
            return Err(Box::new(ConfigurationError::CantBuildAbsolutePath(
                file_name.as_ref().display().to_string(),
            )));
        }

        let config_path = absolute_path.unwrap();

        let config_content = fs::read_to_string(config_path.clone())
            .map_err(|_| ConfigurationError::FileNotFound(config_path.display().to_string()))?;

        let config = Self::from_json(&config_content)?;

        info!(
            "Loaded application configuration from file: {}",
            config_path.display()
        );
        Ok(config)
    }

    pub fn server_address(&self) -> (String, u16) {
        (self.server.host.clone(), self.server.port)
    }
}

impl Default for ApplicationConfiguration {
    fn default() -> Self {
        let msg = format!(
            "Using default embedded configuration (https://github.com/leonidv/oauth2-mock/blob/master/{})",
            DEFAULT_CONFIG_PATH
        );
        info!(msg);

        match Self::from_json(DEFAULT_CONFIG) {
            Ok(config) => config,
            Err(e) => {
                panic!("Failed to parse default configuration: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path;

    use super::*;

    #[test]
    fn parse_config() {
        let app_config = ApplicationConfiguration::from_json(DEFAULT_CONFIG).unwrap();

        let user_config = RegisteredUsers::new(&app_config.users);

        assert_eq!(user_config.users.len(), 2);
        let admin = user_config.users.get("Admin").unwrap();
        assert_eq!(admin.login, "Admin");
        assert_eq!(admin.description, "Administrator of system");

        let user_info = &admin.user_info;
        assert_eq!(user_info.get("login").unwrap(), "admin");
        assert_eq!(user_info.get("id").unwrap(), "1");
        assert_eq!(user_info.get("first_name").unwrap(), "Michael");
        assert_eq!(user_info.get("last_name").unwrap(), "Johnson");
        assert_eq!(user_info.get("display_name").unwrap(), "Admin MJ");
        assert_eq!(user_info.get("default_email").unwrap(), "admin@company.com");

        let manager = user_config.users.get("Manager").unwrap();
        assert_eq!(manager.login, "Manager");
        assert_eq!(manager.description, "Manager works with orders");

        let manager_info = &manager.user_info;
        assert_eq!(manager_info.get("login").unwrap(), "admin");
        assert_eq!(manager_info.get("id").unwrap(), "2");
        assert_eq!(manager_info.get("first_name").unwrap(), "Sarah");
        assert_eq!(manager_info.get("last_name").unwrap(), "Davis");
        assert_eq!(manager_info.get("display_name").unwrap(), "Manager SD");
        assert_eq!(
            manager_info.get("default_email").unwrap(),
            "manager@company.com"
        )
    }

    #[test]
    fn load_config_from_file() {
        let config = ApplicationConfiguration::from_file("config/users.json").unwrap();
        assert_eq!(config.users.len(), 2);
    }

    #[test]
    fn cant_load_nonexistent_config() {
        let absolute_path = path::absolute("config/nonexistent.json").unwrap();
        let result = ApplicationConfiguration::from_file("config/nonexistent.json");

        assert_eq!(result.is_err(), true);
        let expected_message = format!("File not found: {}", absolute_path.display());
        println!("{}", expected_message);
        assert_eq!(result.unwrap_err().to_string(), expected_message,);
    }
}
