use actix_cors::Cors;
use actix_web::{get, http, post, rt, web, App, HttpResponse, HttpServer, Responder};
use chmopass::app_state::AppState;
use serde::Deserialize;
use std::fs;
use env_logger::Env;
use log::{debug, warn, info};
use chmopass::middleware::ChmoPassMiddleWare;
use chmopass::app_config::AppConfig;
use chmopass::token::{refresh_token_loop, ServiceTokenRequest, generate_token};



// Handler for service-to-service token generation
#[post("/service-token")]
async fn generate_service_token(
    service_request: web::Json<ServiceTokenRequest>,
    app_state: web::Data<AppState>
) -> impl Responder {
    // Validate service credentials
    let validated: bool = app_state.config.authorized_services.iter().any(|cred| {
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
        Some(app_state.config.expiration_seconds),
        &app_state.config.private_pem_filename,
    ) {
        Ok(token_response) => {
            info!("Generated token for service: {}", service_request.client_id);
            HttpResponse::Ok().json(token_response)
        },
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
    app_state: web::Data<AppState>,
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
                        if !app_state.config.authorized_github_ids.contains(&github_user.id) {
                            return HttpResponse::Unauthorized().body("Unauthorized user");
                        }
                        // Generate token for the authenticated user
                        match generate_token(
                            format!("github:{}", github_user.id),
                            None,
                            Some("user".to_string()),
                            Some(app_state.config.expiration_seconds),
                            &app_state.config.private_pem_filename,
                        ) {
                            Ok(token_response) => {
                                info!("Generated token for user: {}", github_user.id);
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
    // app state
    let app_state = web::Data::new(AppState {
        config: app_config.clone(),
        token: std::sync::Mutex::new(None),
    });
    // Start token refresh loop
    let app_state_clone = app_state.clone();
    let generate_service_token_url = format!("http://127.0.0.1:{}/service-token", app_state.config.server_port);
    let pem_file = app_state_clone.config.auth.pem_file.clone();
    rt::spawn(async move {
        let _ = refresh_token_loop(app_state_clone, &generate_service_token_url, &pem_file).await;
    });
    // Start HTTP server
    let server_port = app_state.clone().config.server_port;
    HttpServer::new(move || {
        let pem_file = app_state.config.auth.pem_file.clone();
        let _auth = ChmoPassMiddleWare::new(pem_file);
        // In development mode, we allow all origins
        let mut _cors = Cors::default();
        if app_state.config.run_mode == "development" {
            warn!("Development Mode Cors");
            _cors = _cors
                .allow_any_origin()
                .allowed_origin("http://127.0.0.1:3000")
                .allowed_origin("http://localhost:3000")
                .allowed_origin("http://192.168.1.123:3000")
                .allowed_methods(vec!["GET", "POST"])
                .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
                .allowed_header(http::header::CONTENT_TYPE)
                .supports_credentials()
                .max_age(3600);
        }
        App::new()
            .wrap(_cors)
            .app_data(app_state.clone())
            .service(generate_service_token)
            .service(generate_user_token)
            .service(
                web::scope("/secured")
                    .wrap(_auth)
                    .service(status)
            )
    })
    .bind(format!("0.0.0.0:{}", server_port))?
    .run()
    .await
}