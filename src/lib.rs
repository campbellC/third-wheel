//! third-wheel is a TLS man-in-the-middle proxy library. Using the crate allows
//! you to intercept, re-route, modify etc. in-flight HTTP requests and responses
//! between clients and servers. Client code needs to provide a Layer that
//! constructs a Service for intercepting requests and responses. `mitm_layer`
//! provides a convenience function for producing these easily.

//Rustc lints
//<https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html>
#![warn(
    anonymous_parameters,
    bare_trait_objects,
    elided_lifetimes_in_paths,
    missing_copy_implementations,
    rust_2018_idioms,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unsafe_code,
    unused_extern_crates,
    unused_import_braces
)]
// Clippy lints
// <https://rust-lang.github.io/rust-clippy/master/>
#![warn(
    clippy::all,
    clippy::cargo,
    clippy::dbg_macro,
    clippy::float_cmp_const,
    clippy::get_unwrap,
    clippy::mem_forget,
    clippy::nursery,
    clippy::option_unwrap_used,
    clippy::pedantic,
    clippy::result_unwrap_used,
    clippy::todo,
    clippy::wrong_pub_self_convention
)]

mod certificates;
mod proxy;

mod error;

pub use crate::certificates::create_signed_certificate_for_domain;
pub use crate::certificates::CertificateAuthority;
pub use error::Error;
pub use proxy::{
    mitm::{mitm_layer, ThirdWheel},
    MitmProxy, MitmProxyBuilder,
};

pub use hyper;
