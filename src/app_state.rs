use std::sync::Mutex;
use crate::app_config::AppConfig;
use crate::token::ServiceTokenStorage;

pub struct AppState {
    pub config: AppConfig,
    pub token: Mutex<Option<String>>,
}

impl ServiceTokenStorage for AppState {
    fn get_token(&self) -> Option<String> {
        self.token.lock().unwrap().clone()
    }

    fn set_token(&self, token: String) {
        *self.token.lock().unwrap() = Some(token);
    }
    fn get_service_credentials(&self) -> crate::creds::ServiceCredentials {
        self.config.credentials.clone()
    }
}