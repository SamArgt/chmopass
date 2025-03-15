use chrono::TimeZone;
use actix_web::web;
use reqwest;
use log::{info, warn, debug, error};
use serde::{Deserialize, Serialize};
use tokio;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm, DecodingKey, Validation, decode};
use crate::creds::ServiceCredentials;



// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,         // Subject (user ID or service ID)
    pub exp: usize,          // Expiration time
    pub iat: usize,          // Issued at
    pub iss: String,         // Issuer (your pass service)
    pub scope: Option<String>, // Optional scopes
    pub name: Option<String>,  // Optional user name (for user tokens)
}


pub trait ServiceTokenStorage {
    fn get_token(&self) -> Option<String>;
    fn set_token(&self, token: String);
    fn get_service_credentials(&self) -> ServiceCredentials;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServiceTokenRequest {
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_in: usize,
}

// Generate JWT token with the given subject and optional fields
pub fn generate_token(
    subject: String,
    name: Option<String>,
    scope: Option<String>,
    expiration_sec: Option<usize>,
    private_pem_filename: &str,
) -> Result<TokenResponse, jsonwebtoken::errors::Error> {
    // Set token expiration to 1 hour from now
    let expiration_seconds = expiration_sec.unwrap_or(3600);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;
    
    let claims = Claims {
        sub: subject,
        exp: now + expiration_seconds,
        iat: now,
        iss: "pass-service".to_string(),
        scope,
        name,
    };
    
    // Load the private key (in production, consider using environment variables or secure storage)
    let private_key = fs::read(private_pem_filename).expect("Could not read private key file");
    
    // Create a header specifying RS256 algorithm
    let header = Header::new(Algorithm::RS256);
    
    // Encode the token
    let token = encode(&header, &claims, &EncodingKey::from_rsa_pem(&private_key)?)?;
    debug!("Generated token: {:?} from claims {:?}", token, claims);

    // validate token
    let validated = validate_token(&token, "public.pem");
    if validated.is_err() {
        error!("Failed to validate token: {:?}", validated.err());
    } else {
        debug!("Token validated: {:?}", validated.unwrap());
    }


    
    Ok(TokenResponse {
        token,
        expires_in: expiration_seconds,
    })
}


pub fn validate_token<'a>(token: &'a str, public_pem_filename: &'a str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let public_key = fs::read(public_pem_filename).expect("Could not read public key file");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["exp", "iat", "sub"]);
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_rsa_pem(&public_key)?,
        &validation
    )?;
    debug!("Token Claims: {:?}", token_data.claims);
    // Check token is not expired
    let now = chrono::Utc::now();
    let token_expire = chrono::Utc.timestamp_opt(token_data.claims.exp as i64, 0);
    debug!("Token expires at: {:?}", token_expire);
    if let Some(token_expire) = token_expire.single() {
        if token_expire < now {
            return Err(jsonwebtoken::errors::ErrorKind::ExpiredSignature.into());
        }
    }
    Ok(token_data.claims)
}

pub async fn refresh_token_loop<T: ServiceTokenStorage>(token_storage: web::Data<T>, generate_service_token_url: &str, pem_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        info!("Start token refresh loop");
        let service_credentials = token_storage.get_service_credentials();
        let client = reqwest::Client::new();
        let mut sleep_time = tokio::time::Duration::from_secs(30000);
        let response = client
            .post(generate_service_token_url)
            .json(&ServiceTokenRequest {
                client_id: service_credentials.client_id,
                client_secret: service_credentials.client_secret,
                scope: None,
            })
            .send()
            .await;
        if response.is_err() {
            warn!("Failed to call chmopass generation service: {:?}", response.err());
        } else {
            let response = response.unwrap();
            if response.status().is_success() {
                let token_response = response.json::<TokenResponse>().await;
                if token_response.is_err() {
                    warn!("Failed to get jwt token: {:?}", token_response.err());
                } else {
                    let token_response = token_response.unwrap();
                    debug!("Received token: {:?}", token_response.token);
                    let claim = validate_token(&token_response.token, pem_file);
                    if claim.is_err() {
                        warn!("Failed to validate token: {:?}", claim.err());
                    } else {
                        token_storage.set_token(token_response.token);
                        info!("Token refreshed");
                        let claim = claim.unwrap();
                        let expiry = chrono::Utc.timestamp_opt(claim.exp as i64, 0);
                        let now = chrono::Utc::now();
                        let diff_seconds = (expiry.unwrap() - now).num_seconds();
                        info!("Token expires in: {:?}", diff_seconds);
                        sleep_time = tokio::time::Duration::from_secs(diff_seconds as u64);
                    }
                    
                }
            } else {
                warn!("Failed call chmopass generation service with response status: {:?}", response.status());
            }
        }
        tokio::time::sleep(sleep_time).await;
    }
}