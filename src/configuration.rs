use std::{
    collections::HashMap,
    fs,
    path::{self, Path},
};

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Configuration {
    pub authorization_header_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfiguration {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredUsers {
    /// Keys are logins, values are users
    users: HashMap<String, User>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub login: String,
    pub description: String,
    #[serde(rename = "userInfo")]
    pub user_info: HashMap<String, String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationConfiguration {
    pub server: ServerConfiguration,
    pub oauth2: OAuth2Configuration,
    pub users: Vec<User>,
}

/// Used to display help message after loading default configuration
const DEFAULT_CONFIG_PATH: &str = "config/application.json";
const DEFAULT_CONFIG: &str = include_str!("../config/application.json");

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigurationError {
    FileNotFound(String),
    CantBuildAbsolutePath(String),
}

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigurationError::FileNotFound(path) => write!(f, "File not found: {}", path),
            &ConfigurationError::CantBuildAbsolutePath(ref path) => {
                write!(f, "Cant build absolute path: {}", path)
            }
        }
    }
}

impl std::error::Error for ConfigurationError {}

impl RegisteredUsers {
    /// Create a new UserConfiguration from a list of users
    pub fn new(users: &Vec<User>) -> Self {
        Self {
            users: users.into_iter().map(|u| (u.login.clone(), u.clone())).collect(),
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
            Ok(config) => Ok(config),
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

        let user_config = Self::from_json(&config_content)?;

        info!(
            "Loaded application configuration from file: {}",
            config_path.display()
        );
        Ok(user_config)
    }

    pub fn server_address(&self) -> (String, u16) {
        (
            self.server.host.clone(),
            self.server.port,
        )
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
