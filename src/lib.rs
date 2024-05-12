//! A Rust-interface to the [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity/) library.
//!
//! If you're looking for low-level FFI bindings to libmodsecurity, check out [modsecurity-sys](./modsecurity-sys/README.md).

#![deny(missing_docs)]

#[doc(hidden)]
pub mod bindings;

pub mod error;
pub mod intervention;
pub mod msc;
pub mod rules;
pub mod transaction;

pub use error::ModSecurityError;
pub use intervention::Intervention;

/// Common result for a ModSecurity operation.
pub type ModSecurityResult<T> = Result<T, ModSecurityError>;

// Expose a safe interface to subscribers of the crate that makes use of the
// default generic parameters.

/// See [`transaction::Transaction`].
pub type Transaction<'a> = transaction::Transaction<'a>;

/// See [`msc::ModSecurity`].
pub type ModSecurity = msc::ModSecurity;

/// See [`rules::Rules`].
pub type Rules = rules::Rules;
