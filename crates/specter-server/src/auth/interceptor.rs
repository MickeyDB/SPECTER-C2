use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tonic::{Request, Status};

use super::{OperatorContext, TokenInfo};

/// Tonic interceptor that validates auth tokens from gRPC metadata.
///
/// Extracts the `authorization` header, validates it against the in-memory
/// token store, and injects an [`OperatorContext`] into request extensions.
///
/// In dev-mode, authentication is bypassed and a default admin context is
/// injected for every request.
#[derive(Clone)]
pub struct AuthInterceptor {
    tokens: Arc<RwLock<HashMap<String, TokenInfo>>>,
    dev_mode: bool,
}

impl AuthInterceptor {
    pub fn new(tokens: Arc<RwLock<HashMap<String, TokenInfo>>>, dev_mode: bool) -> Self {
        Self { tokens, dev_mode }
    }
}

impl tonic::service::Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        // In dev-mode, bypass authentication and inject a default admin operator.
        if self.dev_mode {
            request
                .extensions_mut()
                .insert(OperatorContext::dev_admin());
            return Ok(request);
        }

        // If authorization header is present, validate it.
        if let Some(token_value) = request.metadata().get("authorization") {
            let token_str = token_value
                .to_str()
                .map_err(|_| Status::unauthenticated("Invalid authorization header"))?;

            // Strip "Bearer " prefix if present.
            let token = token_str.strip_prefix("Bearer ").unwrap_or(token_str);

            let tokens = self
                .tokens
                .read()
                .map_err(|_| Status::internal("Token store lock poisoned"))?;

            if let Some(info) = tokens.get(token) {
                request.extensions_mut().insert(OperatorContext {
                    operator_id: info.operator_id.clone(),
                    username: info.username.clone(),
                    role: info.role.clone(),
                });
            } else {
                return Err(Status::unauthenticated("Invalid token"));
            }
        }

        // If no authorization header is present, the request passes through
        // without an OperatorContext. Individual RPC methods that require auth
        // will check for the OperatorContext in request extensions. This allows
        // the Authenticate RPC to work without an existing token.
        Ok(request)
    }
}
