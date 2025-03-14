use serde::Deserialize;


#[derive(Debug, Deserialize)]
pub struct ServiceCredentials {
    pub client_id: String,
    pub client_secret: String,
}
