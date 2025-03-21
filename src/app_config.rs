use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use std::env;
use crate::creds::ServiceCredentials;


#[derive(Debug, Deserialize, Clone)]
pub struct Auth {
    pub pem_file: String,
    pub disable: bool
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub run_mode: String,
    pub debug_mode: bool,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub expiration_seconds: usize,
    pub private_pem_filename: String,
    pub authorized_github_ids: Vec<i64>,
    pub authorized_services:  Vec<ServiceCredentials>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub credentials: ServiceCredentials,
    pub auth: Auth
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode: String = env::var("CHMOPASS_RUN_MODE").expect("CHMOPASS_RUN_MODE must be set");
        let mut secrets_file = "config/default_services_credentials.json";
        if run_mode == "production" {
            secrets_file = "config/services_credentials.json";
        }
        let s = Config::builder()
            // Start off by merging in the "default" configuration file
            .add_source(File::with_name("config/default"))
            .add_source(File::with_name("config/local.toml").required(false))
            .add_source(File::with_name(secrets_file).required(true))
            // Add in settings from the environment (with a prefix of APP)
            // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
            .set_override("server.run_mode", run_mode)?
            .build()?;
        // You can deserialize (and thus freeze) the entire configuration as
        s.try_deserialize()
    }
}


