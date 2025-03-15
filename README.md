# ChmoPass

## Service
Actix-web server that can generate JWT token for other chmo services and for chmotech-apps.

### Endpoints

- POST `/service-token`
```rust
// Json request
struct ServiceTokenRequest {
    client_id: String,
    client_secret: String,
    #[serde(default)]
    scope: Option<String>,
}
// Json response
struct TokenResponse {
    token: String,
    expires_in: usize,
}

```

- POST `/user-token`
```rust
// Json request
struct UserTokenRequest {
    github_token: String,
}
// Response with Set-Cookie header setting CHMO_TOKEN cookie
bool
```

### Config
- See [config/default.toml](config/default.toml)

### Authorized services
- Create [config/services_credentials.toml](config/services_credentials.toml)

### Env variables

Set `CHMOPASS_RUN_MODE = "development"` or `"production"`

### Pem files
- `private.pem` file to encode JWT Token
- `public.pem` file to decode JWT Token


## Lib

- `chmopass::middleware::ChmopassMiddleWare` middleware to protect chmo services. See [src/main.rs](src/main.rs) for an example.