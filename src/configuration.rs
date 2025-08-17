use std::{
    collections::HashMap,
    fmt::write,
    fs,
    path::{self, Path},
};

use clap::builder::Str;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfiguration {
    pub users: HashMap<String, User>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub login: String,
    pub description: String,
    #[serde(rename = "userInfo")]
    pub user_info: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonConfiguration {
    pub users: Vec<User>,
}

const DEFAULT_CONFIG: &str = include_str!("../config/users.json");

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

impl UserConfiguration {
    /// Create a new UserConfiguration from a list of users
    fn from_users(users: Vec<User>) -> Self {
        Self {
            users: users.into_iter().map(|u| (u.login.clone(), u)).collect(),
        }
    }

    /// Create a new UserConfiguration from a JSON string
    fn from_json(json: &str) -> Result<Self, Box<dyn std::error::Error>> {
        match serde_json::from_str::<JsonConfiguration>(json) {
            Ok(config) => Ok(Self::from_users(config.users)),
            Err(e) => {
                warn!("Failed to parse JSON configuration: {}", e);
                Err(Box::new(e))
            }
        }
    }

    /// Load a user configuration from a file
    pub fn from_file<P: AsRef<Path>>(
        file_name: P,
    ) -> Result<UserConfiguration, Box<dyn std::error::Error>> {
        let absolute_path = path::absolute(file_name.as_ref());

        match absolute_path {
            Ok(config_path) => {
                let config_content = 
                    fs::read_to_string(config_path.clone())
                        .map_err(|_|  ConfigurationError::FileNotFound(config_path.display().to_string()))?;
                let user_config = Self::from_json(&config_content)?;

                info!(
                    "Loaded {} users from configuration file: {}",
                    user_config.users.len(),
                    config_path.display()
                );
                Ok(user_config)
            }
            Err(e) => {
                error!(
                    "Failed to load configuration file: {}, os_error: {}, error: {},",
                    file_name.as_ref().display(),
                    e.raw_os_error()
                        .map_or("unknown".to_string(), |e| e.to_string()),
                    e.to_string(),
                );
                Err(Box::new(ConfigurationError::CantBuildAbsolutePath(
                    file_name.as_ref().display().to_string(),
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path;

    use super::*;

    #[test]
    fn test_from_json() {
        let config = UserConfiguration::from_json(DEFAULT_CONFIG).unwrap();
        assert_eq!(config.users.len(), 2);
        let admin = config.users.get("Admin").unwrap();
        assert_eq!(admin.login, "Admin");
        assert_eq!(admin.description, "Administrator of system");

        let user_info = &admin.user_info;
        assert_eq!(user_info.get("login").unwrap(), "admin");
        assert_eq!(user_info.get("id").unwrap(), "1");
        assert_eq!(user_info.get("first_name").unwrap(), "Michael");
        assert_eq!(user_info.get("last_name").unwrap(), "Johnson");
        assert_eq!(user_info.get("display_name").unwrap(), "Admin MJ");
        assert_eq!(user_info.get("default_email").unwrap(), "admin@company.com");

        let manager = config.users.get("Manager").unwrap();
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
    fn test_load_user_config() {
        let config = UserConfiguration::from_file("config/users.json").unwrap();
        assert_eq!(config.users.len(), 2);
    }

    #[test]
    fn test_cant_load_nonexistent_config() {
        let absolute_path = path::absolute("config/nonexistent.json").unwrap();
        let result = UserConfiguration::from_file("config/nonexistent.json");

        assert_eq!(result.is_err(), true);
        let expected_message = format!("File not found: {}", absolute_path.display());
        println!("{}", expected_message);
        assert_eq!(result.unwrap_err().to_string(), expected_message,);
    }
}
