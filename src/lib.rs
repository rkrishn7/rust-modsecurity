//! A Rust-interface to the [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity/) library.
//!
//! If you're looking for low-level FFI bindings to libmodsecurity, check out [modsecurity-sys](./modsecurity-sys/README.md).

#![warn(missing_docs)]

mod bindings;
mod error;
mod msc;
mod rules;
mod transaction;

pub use error::ModSecurityError;

pub type ModSecurityResult<T> = Result<T, ModSecurityError>;

// Expose a safe interface to subscribers of the crate that makes use of the
// default generic parameters.
pub type Transaction<'a> = transaction::Transaction<'a>;
pub type ModSecurity = msc::ModSecurity;
pub type Rules = rules::Rules;
