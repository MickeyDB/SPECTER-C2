use thiserror::Error;

#[derive(Error, Debug)]
pub enum SpecterError {
    #[error("database error: {0}")]
    Database(String),

    #[error("authentication error: {0}")]
    Auth(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("internal error: {0}")]
    Internal(String),
}
