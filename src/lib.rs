//! A Rust-interface to the [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity/) library.
//!
//! If you're looking for low-level FFI bindings to libmodsecurity, check out [modsecurity-sys](./modsecurity-sys/README.md).

#![warn(missing_docs)]

pub mod bindings;
pub mod error;
pub mod intervention;
pub mod msc;
pub mod rules;
pub mod transaction;

pub use error::ModSecurityError;
pub use intervention::Intervention;

pub type ModSecurityResult<T> = Result<T, ModSecurityError>;

// Expose a safe interface to subscribers of the crate that makes use of the
// default generic parameters.
pub type Transaction<'a> = transaction::Transaction<'a>;
pub type ModSecurity = msc::ModSecurity;
pub type Rules = rules::Rules;
