use std::io;
use thiserror::Error as ThisError;

#[allow(clippy::pub_enum_variant_names)]
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("an error handling server responses")]
    ServerError(String),
    #[error("an error handling client requests")]
    RequestError(String),
    #[error(transparent)]
    HyperError(#[from] hyper::Error),
    #[error(transparent)]
    IOError(#[from] io::Error),
    #[error(transparent)]
    NativeTlsError(#[from] native_tls::Error,),
    #[error(transparent)]
    OpenSslError(#[from] openssl::error::Error),
    #[error(transparent)]
    OpenSslErrorStack(#[from] openssl::error::ErrorStack),
    #[error("A string that should be utf-8 has the wrong encoding")]
    NonUtf8String(String),
    #[error(transparent)]
    InvalidUri(#[from] http::uri::InvalidUri )
}
