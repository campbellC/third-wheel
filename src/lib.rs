//! third-wheel is a TLS man-in-the-middle proxy library. Using the crate allows
//! you to intercept, re-route, modify etc. in-flight HTTP requests and responses
//! between clients and servers. Client code needs to provide a Layer that
//! constructs a Service for intercepting requests and responses. `mitm_layer`
//! provides a convenience function for producing these easily.
//!
//! The best way to see how to use this crate is to take a look at the examples.

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
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::todo,
    clippy::wrong_pub_self_convention
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::redundant_pub_crate // https://github.com/rust-lang/rust-clippy/issues/5369
)]

pub(crate) mod certificates;
pub(crate) mod proxy;

pub(crate) mod error;

pub use crate::certificates::create_signed_certificate_for_domain;
pub use crate::certificates::CertificateAuthority;
pub use error::Error;
pub use proxy::{
    mitm::{mitm_layer, ThirdWheel},
    MitmProxy, MitmProxyBuilder,
};

pub use hyper;
