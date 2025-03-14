use std::{future::{ready, Ready}, rc::Rc, fs};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use log::debug;
use futures_util::future::LocalBoxFuture;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Serialize, Deserialize};


// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,         // Subject (user ID or service ID)
    pub exp: usize,          // Expiration time
    pub iat: usize,          // Issued at
    pub iss: String,         // Issuer (your pass service)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>, // Optional scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,  // Optional user name (for user tokens)
}


fn validate_token<'a>(token: &'a str, public_pem_filename: &'a str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let public_key = fs::read(public_pem_filename).expect("Could not read public key file");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_required_spec_claims(&["exp", "iat", "sub"]);
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_rsa_pem(&public_key)?,
        &validation
    )?;
    debug!("Token data: {:?}", token_data);
    Ok(token_data.claims)
}


#[derive(Clone)]
pub struct ChmoPassMiddleWare {
    public_pem_filename: String,
}

impl ChmoPassMiddleWare {
    pub fn new(public_pem_filename: String) -> Self {
        ChmoPassMiddleWare {
            public_pem_filename,
        }
    }
}


impl<S, B> Transform<S, ServiceRequest> for ChmoPassMiddleWare
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = InnerChmoPassMiddleWare<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(InnerChmoPassMiddleWare { 
            service: Rc::new(service),
            public_pem_filename: Rc::new(self.public_pem_filename.clone())
         }))
    }
}


pub struct InnerChmoPassMiddleWare<S> {
    service: Rc<S>,
    public_pem_filename: Rc<String>,
}

impl<S, B> Service<ServiceRequest> for InnerChmoPassMiddleWare<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let public_pem = self.public_pem_filename.clone().to_string();
        Box::pin(async move {
            let token = req.headers()
                .get("Authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "));
            if let Some(token) = token {
                let token = token.to_string();
                match validate_token(&token, &public_pem) {
                    Ok(_) => {
                        let res = service.call(req).await?;
                        Ok(res)
                    },
                    Err(_) => {
                        Err(actix_web::error::ErrorUnauthorized("Invalid token"))
                    }
                }
            } else {
                Err(actix_web::error::ErrorUnauthorized("No token provided"))
            }
        })
    }
}