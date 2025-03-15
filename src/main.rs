use actix_web::{web, App, HttpResponse, HttpServer, Responder, post, get};
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use env_logger::Env;
use log::{debug, warn};
use chmopass::middleware::{Claims, ChmoPassMiddleWare};
use chmopass::app_config::AppConfig;


#[derive(Debug, Serialize)]
struct TokenResponse {
    token: String,
    expires_in: usize,
}

// Generate JWT token with the given subject and optional fields
fn generate_token(
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
    
    Ok(TokenResponse {
        token,
        expires_in: expiration_seconds,
    })
}

#[derive(Debug, Deserialize)]
struct ServiceTokenRequest {
    client_id: String,
    client_secret: String,
    #[serde(default)]
    scope: Option<String>,
}

// Handler for service-to-service token generation
#[post("/service-token")]
async fn generate_service_token(
    service_request: web::Json<ServiceTokenRequest>,
    config: web::Data<AppConfig>
) -> impl Responder {
    // Validate service credentials
    let validated: bool = config.authorized_services.iter().any(|cred| {
        cred.client_id == service_request.client_id && cred.client_secret == service_request.client_secret
    });
    if !validated {
        return HttpResponse::Unauthorized().body("Invalid client credentials");
    }
    // Generate token for the authenticated service
    match generate_token(
        service_request.client_id.clone(),
        None,
        service_request.scope.clone(),
        Some(config.expiration_seconds),
        &config.private_pem_filename,
    ) {
        Ok(token_response) => HttpResponse::Ok().json(token_response),
        Err(_) => HttpResponse::InternalServerError().body("Failed to generate token"),
    }
}

#[derive(Debug, Deserialize)]
struct UserTokenRequest {
    github_token: String,
}

#[derive(Debug, Deserialize)]
struct GithubUser {
    id: i64,
}



// Handler for user token generation via GitHub authentication
#[post("/user-token")]
async fn generate_user_token(
    user_request: web::Json<UserTokenRequest>,
    config: web::Data<AppConfig>,
) -> impl Responder {
    // Verify GitHub token by making a request to GitHub API
    let github_response = reqwest::Client::new()
        .get("https://api.github.com/user")
        .header("Authorization", format!("token {}", user_request.github_token))
        .header("User-Agent", "pass-service") // GitHub API requires a user agent
        .send()
        .await;
    
    match github_response {
        Ok(response) => {
            if response.status().is_success() {
                // Parse GitHub user data
                match response.json::<GithubUser>().await {
                    Ok(github_user) => {
                        // Check if the user is authorized
                        if !config.authorized_github_ids.contains(&github_user.id) {
                            return HttpResponse::Unauthorized().body("Unauthorized user");
                        }
                        // Generate token for the authenticated user
                        match generate_token(
                            format!("github:{}", github_user.id),
                            None,
                            Some("user".to_string()),
                            Some(config.expiration_seconds),
                            &config.private_pem_filename,
                        ) {
                            Ok(token_response) => {
                                // Set-Cookie header with expiration time
                                let cookie = format!(
                                    "CHMO_TOKEN={}; Max-Age={}; Secure; HttpOnly; SameSite=Strict",
                                    token_response.token,
                                    token_response.expires_in,
                                );
                                HttpResponse::Ok().append_header(("Set-Cookie", cookie)).json(true)
                        },
                            Err(_) => HttpResponse::InternalServerError().body("Failed to generate token"),
                        }
                    },
                    Err(_) => HttpResponse::InternalServerError().body("Failed to parse GitHub response"),
                }
            } else {
                HttpResponse::Unauthorized().body("Invalid GitHub token")
            }
        },
        Err(_) => HttpResponse::InternalServerError().body("Failed to verify GitHub token"),
    }
}

#[get("/status")]
async fn status() -> impl Responder {
    HttpResponse::Ok().body("Chmopass service is running!")
}

// Main function to start the server
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv::dotenv().ok();
    // Load config
    let app_config = AppConfig::new().expect("Failed to load configuration");
    // Logger
    let mut log_level = "chmopass=info";
    if app_config.debug {
        log_level = "chmopass=debug,info";
    }
    let env = Env::default()
        .default_filter_or(log_level)
        .default_write_style_or("auto");
    env_logger::init_from_env(env);
    warn!("Starting chmosec-service in {} mode", app_config.run_mode);
    debug!("Config: {:?}", app_config);
    // Check private key file
    fs::metadata(&app_config.private_pem_filename).expect("Private key file not found");
    // Check service credentials are not default in production
    if app_config.run_mode == "production" {
        if app_config.credentials.client_id == "chmopass" {
                panic!("Service credentials are default in production");
        }
    }
    // Start HTTP server
    let app_state = web::Data::new(app_config);
    let server_port = app_state.clone().server_port;
    HttpServer::new(move || {
        let pem_file = app_state.auth.pem_file.clone();
        let _auth = ChmoPassMiddleWare::new(pem_file);
        App::new()
            .app_data(app_state.clone())
            .service(generate_service_token)
            .service(generate_user_token)
            .service(
                web::scope("/secured")
                    .wrap(_auth)
                    .service(status)
            )
    })
    .bind(format!("127.0.0.1:{}", server_port))?
    .run()
    .await
}