use std::{
    collections::HashMap,
    path::{self, Path},
};

use config::{Config, Environment, File, FileFormat};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::authorization;

#[derive(Debug)]
pub enum ConfigurationError {
    Io(std::io::Error),
    BadJson(serde_json::Error),
    Config(config::ConfigError),
    FileNotFound(String),
    NoUsers,
    AccessRestrictionEnabledWithoutCode,
    AccessRestrictionSignKeyIsTooShort,
}

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigurationError::FileNotFound(path) => write!(f, "File not found: {}", path),
            ConfigurationError::NoUsers => {
                write!(f, "Config must contains list of users")
            }
            &ConfigurationError::AccessRestrictionEnabledWithoutCode => {
                write!(f, "Access restriction is enabled, but code is empty.")
            }
            ConfigurationError::AccessRestrictionSignKeyIsTooShort => {
                write!(
                    f,
                    "Access restriction sign key should be greater then 64 characters"
                )
            }
            ConfigurationError::BadJson(serde_err) => {
                write!(f, "{}", serde_err)
            }
            ConfigurationError::Config(config_err) => {
                write!(f, "{}", config_err)
            }
            ConfigurationError::Io(io_err) => {
                write!(f, "{}", io_err)
            }
        }
    }
}

impl std::error::Error for ConfigurationError {}

impl From<serde_json::Error> for ConfigurationError {
    fn from(value: serde_json::Error) -> Self {
        ConfigurationError::BadJson(value)
    }
}

impl From<std::io::Error> for ConfigurationError {
    fn from(value: std::io::Error) -> Self {
        ConfigurationError::Io(value)
    }
}

impl From<config::ConfigError> for ConfigurationError {
    fn from(value: config::ConfigError) -> Self {
        ConfigurationError::Config(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuth2Configuration {
    pub authorization_header_prefix: String,
}

/// Network server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ApplicationConfiguration {
    pub server: ServerConfiguration,
    pub oauth2: OAuth2Configuration,
    pub access_restriction: AccessRestriction,
    pub users: Vec<User>,
}

/// Used to display help message after loading default configuration
const DEFAULT_CONFIG_PATH: &str = "config/application.json";
const DEFAULT_CONFIG: &str = include_str!("../config/application.json");
const ENV_PREFIX: &str = "OAUTH2_MOCK";

#[derive(Debug, Clone, Default)]
pub struct ConfigurationOverrides {
    pub server_host: Option<String>,
    pub server_port: Option<u16>,
}

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
    /// Create an application configuration from a complete JSON document.
    /// `allow_no_users` is only used by validation tests.
    fn from_json(json: &str, allow_no_users: bool) -> Result<Self, ConfigurationError> {
        let mut config = serde_json::from_str::<ApplicationConfiguration>(json)?;
        config.validate_and_finalize(allow_no_users)?;
        Ok(config)
    }

    fn validate_and_finalize(&mut self, allow_no_users: bool) -> Result<(), ConfigurationError> {
        if self.users.is_empty() && !allow_no_users {
            return Err(ConfigurationError::NoUsers);
        }

        let access_restriction = &self.access_restriction;
        if access_restriction.enabled {
            if access_restriction.code.is_empty() {
                return Err(ConfigurationError::AccessRestrictionEnabledWithoutCode);
            }

            let sign_key_len = access_restriction.sign_key.len();
            if sign_key_len > 0 && sign_key_len < 64 {
                return Err(ConfigurationError::AccessRestrictionSignKeyIsTooShort);
            }
        }

        if !access_restriction.enabled || access_restriction.sign_key.is_empty() {
            // Generate a valid runtime key after all configuration layers are applied.
            self.access_restriction.sign_key = authorization::generate_sign_key();
        }

        Ok(())
    }

    fn environment_source(source: Option<HashMap<String, String>>) -> Environment {
        Environment::with_prefix(ENV_PREFIX)
            .prefix_separator("_")
            .separator("__")
            .source(source)
    }

    fn load_from_sources(
        config_path: Option<&Path>,
        environment: Environment,
        overrides: &ConfigurationOverrides,
    ) -> Result<Self, ConfigurationError> {
        let mut builder =
            Config::builder().add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Json));

        if let Some(file_name) = config_path {
            let absolute_path = path::absolute(file_name)?;
            if !absolute_path.exists() {
                return Err(ConfigurationError::FileNotFound(
                    absolute_path.display().to_string(),
                ));
            }

            info!("Load configuration from file: {}", absolute_path.display());
            builder = builder.add_source(File::from(absolute_path).format(FileFormat::Json));
        } else {
            info!(
                "Using default embedded configuration (https://github.com/leonidv/oauth2-mock/blob/master/{})",
                DEFAULT_CONFIG_PATH
            );
        }

        let mut config = builder
            .add_source(environment)
            .set_override_option("server.host", overrides.server_host.clone())?
            .set_override_option("server.port", overrides.server_port)?
            .build()?
            .try_deserialize::<ApplicationConfiguration>()?;

        config.validate_and_finalize(false)?;
        Ok(config)
    }

    /// Load all production configuration layers.
    ///
    /// Priority, from lowest to highest: embedded JSON, optional external JSON,
    /// `OAUTH2_MOCK_*` environment variables, explicit CLI overrides.
    pub fn load(
        config_path: Option<&Path>,
        overrides: &ConfigurationOverrides,
    ) -> Result<Self, ConfigurationError> {
        Self::load_from_sources(config_path, Self::environment_source(None), overrides)
    }

    /// Load an external JSON layer over the embedded defaults.
    ///
    /// Environment variables are deliberately not read by this method. Use [`Self::load`]
    /// for the complete production source chain.
    pub fn from_file<P: AsRef<Path>>(
        file_name: P,
    ) -> Result<ApplicationConfiguration, ConfigurationError> {
        Self::load_from_sources(
            Some(file_name.as_ref()),
            Self::environment_source(Some(HashMap::new())),
            &ConfigurationOverrides::default(),
        )
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

        match Self::from_json(DEFAULT_CONFIG, false) {
            Ok(config) => config,
            Err(e) => {
                panic!("Failed to parse default configuration: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::{
        io::Write,
        path::{self, Path},
    };
    use tempfile::NamedTempFile;

    fn temporary_config(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    fn test_environment(entries: &[(&str, &str)]) -> Environment {
        let source = entries
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        ApplicationConfiguration::environment_source(Some(source))
    }

    fn load_for_test(
        config_path: Option<&Path>,
        environment: &[(&str, &str)],
        overrides: &ConfigurationOverrides,
    ) -> Result<ApplicationConfiguration, ConfigurationError> {
        ApplicationConfiguration::load_from_sources(
            config_path,
            test_environment(environment),
            overrides,
        )
    }

    #[test]
    fn parse() {
        let app_config = ApplicationConfiguration::default();

        let user_config = RegisteredUsers::new(&app_config.users);

        let server = &app_config.server;
        assert_eq!(server.host, "0.0.0.0");
        assert_eq!(server.port, 3000);

        let access_restriction = &app_config.access_restriction;
        assert!(!access_restriction.enabled);
        assert_eq!(access_restriction.code, "");
        assert_eq!(access_restriction.sign_key.len(), 64); // code is generated

        assert_eq!(user_config.users.len(), 2);
        let admin = user_config.users.get("admin").unwrap();
        assert_eq!(admin.login, "admin");
        assert_eq!(admin.description, "Administrator of system");

        let user_info = &admin.user_info;
        assert_eq!(user_info.get("login").unwrap(), "admin");
        assert_eq!(user_info.get("id").unwrap(), "1");
        assert_eq!(user_info.get("first_name").unwrap(), "Michael");
        assert_eq!(user_info.get("last_name").unwrap(), "Johnson");
        assert_eq!(user_info.get("display_name").unwrap(), "Admin MJ");
        assert_eq!(user_info.get("default_email").unwrap(), "admin@company.com");

        let manager = user_config.users.get("manager").unwrap();
        assert_eq!(manager.login, "manager");
        assert_eq!(manager.description, "Manager works with orders");

        let manager_info = &manager.user_info;
        assert_eq!(manager_info.get("login").unwrap(), "manager");
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
    fn load_from_file() {
        let config = ApplicationConfiguration::from_file("config/application.json").unwrap();
        assert_eq!(config.users.len(), 2);
    }

    #[test]
    fn empty_external_config_keeps_embedded_defaults() {
        let file = temporary_config("{}");
        let config = ApplicationConfiguration::from_file(file.path()).unwrap();

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.oauth2.authorization_header_prefix, "Bearer");
        assert_eq!(config.users.len(), 2);
    }

    #[test]
    fn external_file_overrides_only_present_fields() {
        let file = temporary_config(r#"{ "server": { "port": 8080 } }"#);
        let config = ApplicationConfiguration::from_file(file.path()).unwrap();

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.oauth2.authorization_header_prefix, "Bearer");
        assert_eq!(config.users.len(), 2);
    }

    #[test]
    fn external_file_recursively_merges_nested_sections() {
        let file = temporary_config(
            r#"{
                "access_restriction": {
                    "enabled": true,
                    "code": "secret"
                }
            }"#,
        );
        let config = ApplicationConfiguration::from_file(file.path()).unwrap();

        assert!(config.access_restriction.enabled);
        assert_eq!(config.access_restriction.code, "secret");
        assert_eq!(config.access_restriction.sign_key.len(), 64);
        assert_eq!(config.server.port, 3000);
    }

    #[test]
    fn external_users_replace_embedded_users() {
        let file = temporary_config(
            r#"{
                "users": [
                    {
                        "login": "tester",
                        "description": "Test user",
                        "userInfo": {
                            "id": "42",
                            "custom_claim": "value"
                        }
                    }
                ]
            }"#,
        );
        let config = ApplicationConfiguration::from_file(file.path()).unwrap();

        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].login, "tester");
        assert_eq!(
            config.users[0].user_info.get("custom_claim").unwrap(),
            "value"
        );
    }

    #[test]
    fn empty_users_override_is_rejected() {
        let file = temporary_config(r#"{ "users": [] }"#);
        let error = ApplicationConfiguration::from_file(file.path()).unwrap_err();

        assert!(matches!(error, ConfigurationError::NoUsers));
    }

    #[test]
    fn environment_overrides_embedded_values() {
        let config = load_for_test(
            None,
            &[
                ("OAUTH2_MOCK_SERVER__HOST", "127.0.0.1"),
                ("OAUTH2_MOCK_SERVER__PORT", "8080"),
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__ENABLED", "true"),
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__CODE", "secret"),
            ],
            &ConfigurationOverrides::default(),
        )
        .unwrap();

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert!(config.access_restriction.enabled);
        assert_eq!(config.access_restriction.code, "secret");
    }

    #[test]
    fn environment_preserves_string_values_verbatim() {
        let config = load_for_test(
            None,
            &[
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__ENABLED", "true"),
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__CODE", "000123"),
            ],
            &ConfigurationOverrides::default(),
        )
        .unwrap();

        assert_eq!(config.access_restriction.code, "000123");
    }

    #[test]
    fn environment_preserves_snake_case_with_double_underscore_separator() {
        let config = load_for_test(
            None,
            &[("OAUTH2_MOCK_OAUTH2__AUTHORIZATION_HEADER_PREFIX", "Token")],
            &ConfigurationOverrides::default(),
        )
        .unwrap();

        assert_eq!(config.oauth2.authorization_header_prefix, "Token");
    }

    #[test]
    fn environment_with_wrong_prefix_is_ignored() {
        let config = load_for_test(
            None,
            &[("OTHER_SERVER__PORT", "8080")],
            &ConfigurationOverrides::default(),
        )
        .unwrap();

        assert_eq!(config.server.port, 3000);
    }

    #[test]
    fn empty_environment_value_is_an_explicit_override() {
        let error = load_for_test(
            None,
            &[
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__ENABLED", "true"),
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__CODE", ""),
            ],
            &ConfigurationOverrides::default(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ConfigurationError::AccessRestrictionEnabledWithoutCode
        ));
    }

    #[test]
    fn invalid_environment_port_is_rejected() {
        let error = load_for_test(
            None,
            &[("OAUTH2_MOCK_SERVER__PORT", "not-a-number")],
            &ConfigurationOverrides::default(),
        )
        .unwrap_err();

        assert!(matches!(error, ConfigurationError::Config(_)));
        assert!(error.to_string().contains("server.port"));
    }

    #[test]
    fn out_of_range_environment_port_is_rejected() {
        let error = load_for_test(
            None,
            &[("OAUTH2_MOCK_SERVER__PORT", "70000")],
            &ConfigurationOverrides::default(),
        )
        .unwrap_err();

        assert!(matches!(error, ConfigurationError::Config(_)));
    }

    #[rstest]
    #[case(None, None, None, 3000)]
    #[case(Some(4000), None, None, 4000)]
    #[case(Some(4000), Some(5000), None, 5000)]
    #[case(Some(4000), Some(5000), Some(6000), 6000)]
    fn respects_source_precedence(
        #[case] file_port: Option<u16>,
        #[case] environment_port: Option<u16>,
        #[case] cli_port: Option<u16>,
        #[case] expected: u16,
    ) {
        let file = file_port
            .map(|port| temporary_config(&format!(r#"{{ "server": {{ "port": {port} }} }}"#)));
        let environment_value = environment_port.map(|port| port.to_string());
        let environment = environment_value
            .as_deref()
            .map(|port| vec![("OAUTH2_MOCK_SERVER__PORT", port)])
            .unwrap_or_default();
        let overrides = ConfigurationOverrides {
            server_host: None,
            server_port: cli_port,
        };

        let config = load_for_test(
            file.as_ref().map(NamedTempFile::path),
            &environment,
            &overrides,
        )
        .unwrap();

        assert_eq!(config.server.port, expected);
    }

    #[test]
    fn environment_can_complete_partial_file() {
        let file = temporary_config(r#"{ "access_restriction": { "enabled": true } }"#);
        let config = load_for_test(
            Some(file.path()),
            &[("OAUTH2_MOCK_ACCESS_RESTRICTION__CODE", "secret")],
            &ConfigurationOverrides::default(),
        )
        .unwrap();

        assert!(config.access_restriction.enabled);
        assert_eq!(config.access_restriction.code, "secret");
    }

    #[test]
    fn higher_priority_short_sign_key_is_rejected() {
        let error = load_for_test(
            None,
            &[
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__ENABLED", "true"),
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__CODE", "secret"),
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__SIGN_KEY", "short"),
            ],
            &ConfigurationOverrides::default(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ConfigurationError::AccessRestrictionSignKeyIsTooShort
        ));
    }

    #[test]
    fn valid_sign_key_from_environment_is_preserved() {
        let sign_key = "a".repeat(64);
        let config = load_for_test(
            None,
            &[
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__ENABLED", "true"),
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__CODE", "secret"),
                ("OAUTH2_MOCK_ACCESS_RESTRICTION__SIGN_KEY", &sign_key),
            ],
            &ConfigurationOverrides::default(),
        )
        .unwrap();

        assert_eq!(config.access_restriction.sign_key, sign_key);
    }

    #[test]
    fn invalid_external_json_is_rejected() {
        let file = temporary_config(r#"{ "server": { "port": 8080, } }"#);
        let error = ApplicationConfiguration::from_file(file.path()).unwrap_err();

        assert!(matches!(error, ConfigurationError::Config(_)));
        assert!(
            error
                .to_string()
                .contains(&file.path().display().to_string())
        );
    }

    #[test]
    fn null_does_not_fall_back_to_embedded_value() {
        let file = temporary_config(r#"{ "server": { "port": null } }"#);
        let error = ApplicationConfiguration::from_file(file.path()).unwrap_err();

        assert!(matches!(error, ConfigurationError::Config(_)));
    }

    #[test]
    fn unknown_file_field_is_rejected() {
        let file = temporary_config(r#"{ "server": { "prt": 8080 } }"#);
        let error = ApplicationConfiguration::from_file(file.path()).unwrap_err();

        assert!(matches!(error, ConfigurationError::Config(_)));
        assert!(error.to_string().contains("prt"));
    }

    #[test]
    fn unknown_environment_field_is_rejected() {
        let error = load_for_test(
            None,
            &[("OAUTH2_MOCK_SERVER__PRT", "8080")],
            &ConfigurationOverrides::default(),
        )
        .unwrap_err();

        assert!(matches!(error, ConfigurationError::Config(_)));
        assert!(error.to_string().contains("prt"));
    }

    #[test]
    fn cant_load_nonexistent_config() {
        let absolute_path = path::absolute("config/nonexistent.json").unwrap();
        let result = ApplicationConfiguration::from_file("config/nonexistent.json");

        assert!(result.is_err());
        let expected_message = format!("File not found: {}", absolute_path.display());
        assert_eq!(result.unwrap_err().to_string(), expected_message);
    }

    #[test]
    fn no_users_error() {
        let json = r#"
        {
            "server": {
                "host": "0.0.0.0",
                "port": 3000
            },  
            "oauth2": {
                "authorization_header_prefix": "Bearer"
            },
            "access_restriction": {
                "enabled": true,
                "code":"1",
                "sign_key":""
            },
            "users": [ ]
        }"#;

        let result = ApplicationConfiguration::from_json(json, false);
        let err = result.expect_err("Should be error");
        assert!(
            matches!(err, ConfigurationError::NoUsers),
            "expected {:?}, actual {:?}",
            ConfigurationError::NoUsers,
            err
        );
    }

    #[test]
    fn enabled_config_restriction_without_code() {
        let json = r#"
                {
                "server": {
                    "host": "0.0.0.0",
                    "port": 3000
                },  
                "oauth2": {
                    "authorization_header_prefix": "Bearer"
                },
                "access_restriction": {
                    "enabled": true,
                    "code":"",
                    "sign_key":""
                },
                "users": []
                }"#;
        let result = ApplicationConfiguration::from_json(json, true);
        let err = result.expect_err("Should be error");
        assert!(
            matches!(err, ConfigurationError::AccessRestrictionEnabledWithoutCode),
            "expected {:?}, actual: {:?}",
            ConfigurationError::AccessRestrictionEnabledWithoutCode,
            err
        )
    }

    #[test]
    fn enabled_config_sign_key_too_short() {
        let json = r#"
                {
                "server": {
                    "host": "0.0.0.0",
                    "port": 3000
                },  
                "oauth2": {
                    "authorization_header_prefix": "Bearer"
                },
                "access_restriction": {
                    "enabled": true,
                    "code":"123",
                    "sign_key":"aaaa"
                },
                "users": []
                }"#;
        let result = ApplicationConfiguration::from_json(json, true);
        let err = result.expect_err("Should be error");
        assert!(
            matches!(err, ConfigurationError::AccessRestrictionSignKeyIsTooShort),
            "expected {:?}, actual: {:?}",
            ConfigurationError::AccessRestrictionSignKeyIsTooShort,
            err
        )
    }
}
