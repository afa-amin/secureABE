use thiserror::Error;

#[derive(Debug, Error)]
pub enum AbeError {
    #[error("attribute '{0}' is not registered in the public parameters")]
    UnknownAttribute(String),
    #[error("the held attribute set does not satisfy the ciphertext policy")]
    PolicyNotSatisfied,
    #[error("symmetric unwrap of the data key failed: {0}")]
    UnwrapFailed(String),
    #[error("invalid key or ciphertext encoding: {0}")]
    Encoding(String),
}
