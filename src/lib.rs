mod certificates;

mod http_proxy;

mod codecs;

#[macro_use]
extern crate lazy_static;

pub use crate::certificates::create_signed_certificate_for_domain;
pub use crate::certificates::CA;
pub use http_proxy::{run_http_proxy, start_mitm, RequestCapture, ResponseCapture, MitmLayer};

pub type SafeResult = Result<(), Box<dyn std::error::Error>>;
