use serde::Deserialize;


#[derive(Debug, Deserialize, Clone)]
pub struct ServiceCredentials {
    pub client_id: String,
    pub client_secret: String,
}
