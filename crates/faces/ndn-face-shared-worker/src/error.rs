use thiserror::Error;

#[derive(Debug, Error)]
pub enum SharedWorkerFaceError {
    #[error("not running in a SharedWorker scope")]
    NotInWorkerScope,
    #[error("SharedWorker construction failed: {0}")]
    Construct(String),
    #[error("port handshake failed: {0}")]
    Handshake(String),
    #[error("port closed")]
    Closed,
}
