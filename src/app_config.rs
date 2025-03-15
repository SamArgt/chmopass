use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::env;
use crate::creds::ServiceCredentials;


#[derive(Debug, Deserialize)]
pub struct Auth {
    pub pem_file: String
}


#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub server_port: u16,
    pub expiration_seconds: usize,
    pub private_pem_filename: String,
    pub debug: bool,
    pub run_mode: String,
    pub authorized_services:  Vec<ServiceCredentials>,
    pub authorized_github_ids: Vec<i64>,
    pub credentials: ServiceCredentials,
    pub auth: Auth
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("CHMOPASS_RUN_MODE").expect("CHMOPASS_RUN_MODE must be set");
        let mut secrets_file = "config/default_services_credentials.json";
        if run_mode == " production" {
            secrets_file = "config/services_credentials.json";
        }
        let s = Config::builder()
            // Start off by merging in the "default" configuration file
            .add_source(File::with_name("config/default"))
            .add_source(File::with_name("config/local.toml").required(false))
            .add_source(File::with_name(secrets_file).required(true))
            // Add in settings from the environment (with a prefix of APP)
            // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
            .add_source(Environment::with_prefix("CHMOSEC_APP"))
            .set_override("run_mode", run_mode)?
            .build()?;

        // Now that we're done, let's access our configuration
        println!("debug: {:?}", s.get_bool("debug"));

        // You can deserialize (and thus freeze) the entire configuration as
        s.try_deserialize()
    }
}