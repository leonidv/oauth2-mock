use std::{collections::HashMap, fs, path::Path};

use clap::builder::Str;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfiguration {
   pub  users: HashMap<String, User>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
   pub login: String,
   pub description: String,
   #[serde(rename= "userInfo")]
   pub user_info: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonConfiguration {
    pub users: Vec<User>
}

const DEFAULT_CONFIG: &str = include_str!("../config/users.json");

#[derive(Debug, Clone)]
pub enum ConfigurationError {
    FileNotFound(String),
}

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigurationError::FileNotFound(path) => 
            write!(f, "File not found: {}", path),
        }
    }
}

impl std::error::Error for ConfigurationError{}

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
            Ok(config) => {
                Ok(Self::from_users(config.users))
            },
            Err(e) => {
                warn!("Failed to parse JSON configuration: {}", e);
                Err(Box::new(e))
            }
        }
    }

    /// Load a user configuration from a file
    pub fn from_file<P: AsRef<Path>>(
        config_path: P,
    ) -> Result<UserConfiguration, Box<dyn std::error::Error>> {
        let config_path = config_path.as_ref();
        if !config_path.exists() {
            let e = ConfigurationError::FileNotFound(config_path.display().to_string());
            return Err(Box::new(e))
        }

        let config_content = fs::read_to_string(config_path)?;
        let user_config = Self::from_json(&config_content)?;


        info!(
            "Loaded {} users from configuration file: {}",
            user_config.users.len(),
            config_path.display()
        );

        Ok(user_config)
    }
}

#[cfg(test)] mod tests {
    use super::*;

    #[test]
    fn test_from_json() {
        let config = UserConfiguration::from_json(DEFAULT_CONFIG).unwrap();
        assert_eq!(config.users.len(), 2);
    }

    #[test]
    fn test_load_user_config() {
        let config = UserConfiguration::from_file("config/users.json").unwrap();
        assert_eq!(config.users.len(), 2);
    }
}