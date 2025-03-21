use std::{future::{ready, Ready}, rc::Rc};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::LocalBoxFuture;
use crate::token::validate_token;


#[derive(Clone)]
pub struct ChmoPassMiddleWare {
    public_pem_filename: String,
    disable: bool,
}

impl ChmoPassMiddleWare {
    pub fn new(public_pem_filename: String, disable: Option<bool>) -> Self {
        ChmoPassMiddleWare {
            public_pem_filename: public_pem_filename,
            disable: disable.unwrap_or(false),
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
            public_pem_filename: Rc::new(self.public_pem_filename.clone()),
            disable: self.disable,
         }))
    }
}


pub struct InnerChmoPassMiddleWare<S> {
    service: Rc<S>,
    public_pem_filename: Rc<String>,
    disable: bool,
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
        if self.disable {
            return Box::pin(async move {
                let res = service.call(req).await?;
                Ok(res)
            });
        }
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