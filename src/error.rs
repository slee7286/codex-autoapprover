use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("hook input exceeds the {0}-byte limit")]
    InputTooLarge(usize),
    #[error("hook input is not a JSON object")]
    NotAnObject,
    #[error("hook input is malformed JSON")]
    InvalidJson(#[from] serde_json::Error),
    #[error("hook input contains trailing data")]
    TrailingData,
}
